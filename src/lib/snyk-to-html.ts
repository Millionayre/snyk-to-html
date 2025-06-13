#!/usr/bin/env node

import * as isEmpty from 'lodash.isempty';
import * as orderBy from 'lodash.orderby';
import chalk from 'chalk';
import * as debugModule from 'debug';
import * as fs from 'node:fs';
import * as Handlebars from 'handlebars';
import * as marked from 'marked';
import * as path from 'node:path';
import {
  addIssueDataToPatch,
  getUpgrades,
  IacProjectType,
  severityMap,
} from './vuln';
import { processSourceCode } from './codeutil';
import { formatDateTime } from './dateutil';

const debug = debugModule('snyk-to-html');

const defaultRemediationText =
  '## Remediation\nThere is no remediation at the moment';

function readFile(filePath: fs.PathOrFileDescriptor): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    fs.readFile(filePath, { encoding: 'utf-8' }, (err, data) => {
      if (err) {
        reject(err);
      }
      resolve(data);
    });
  });
}

function handleInvalidJson(reason: any) {
  if (reason.isInvalidJson) {
    reason.message =
      reason.message +
      'Error running `snyk-to-html`. Please check you are providing the correct parameters. ' +
      'Is the issue persists contact support@snyk.io';
  }
  console.log(reason.message);
}

function promisedParseJSON(json: string): Promise<any> {
  return new Promise((resolve, reject) => {
    try {
      resolve(JSON.parse(json));
    } catch (error) {
      if (error instanceof Error) {
        error.message = chalk.red.bold(
          'The source provided is not a valid json! Please validate that the input provided to the CLI is an actual JSON\n\n' +
            'Tip: To find more information, try running `snyk-to-html` in debug mode by appending to the CLI the `-d` parameter\n\n',
        );
        debug(`Input provided to the CLI: \n${json}\n\n`);
        (error as any).isInvalidJson = true;
        reject(error);
      } else {
        reject(new Error('An unknown error occurred'));
      }
    }
  });
}

class SnykToHtml {
  public static run(
    dataSource: string,
    remediation: boolean,
    hbsTemplate: string,
    summary: boolean,
    reportCallback: (value: string) => void,
  ): void {
    SnykToHtml.runAsync(dataSource, remediation, hbsTemplate, summary)
      .then(reportCallback)
      .catch(handleInvalidJson);
  }

  public static async runAsync(
    source: string,
    remediation: boolean,
    template: string,
    summary: boolean,
  ): Promise<string> {
    const promisedString = source ? readFile(source) : readInputFromStdin();
    return promisedString.then(promisedParseJSON).then((data: any) => {
      const usingModern = isModernTemplate(template);
      if (
        data?.infrastructureAsCodeIssues ||
        data[0]?.infrastructureAsCodeIssues
      ) {
        // Preserve modern template selection for IaC reports
        template = usingModern
          ? path.join(__dirname, '../../template/modernized-sca-report.hbs')
          : template === path.join(__dirname, '../../template/test-report.hbs')
          ? path.join(__dirname, '../../template/iac/test-report.hbs')
          : template;
        return processIacData(data, template, summary);
      } else if (data?.runs && data?.runs[0].tool.driver.name === 'SnykCode') {
        // Preserve modern template selection for Code reports
        template = usingModern
          ? path.join(__dirname, '../../template/modernized-sca-report.hbs')
          : template === path.join(__dirname, '../../template/test-report.hbs')
          ? path.join(__dirname, '../../template/code/test-report.hbs')
          : template;
        return processCodeData(data, template, summary);
      } else if (data.docker) {
        return processContainerData(data, remediation, template, summary);
      } else {
        return processData(data, remediation, template, summary);
      }
    });
  }
}

function metadataForVuln(vuln: any) {
  const { cveSpaced, cveLineBreaks } = concatenateCVEs(vuln);

  return {
    id: vuln.id,
    title: vuln.title,
    name: vuln.name,
    info: vuln.info || 'No information available.',
    severity: vuln.severity,
    severityValue: severityMap[vuln.severity],
    description: vuln.description || 'No description available.',
    fixedIn: vuln.fixedIn,
    packageManager: vuln.packageManager,
    version: vuln.version,
    cvssScore: vuln.cvssScore,
    cveSpaced: cveSpaced || 'No CVE found.',
    cveLineBreaks: cveLineBreaks || 'No CVE found.',
    disclosureTime: dateFromDateTimeString(vuln.disclosureTime || ''),
    publicationTime: dateFromDateTimeString(vuln.publicationTime || ''),
    license: vuln.license || undefined,
  };
}

function concatenateCVEs(vuln: any) {
  let cveSpaced = '';
  let cveLineBreaks = '';

  if (vuln.identifiers) {
    vuln.identifiers.CVE.forEach(function(c) {
      const cveLink = `<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${c}">${c}</a>`;
      cveSpaced += `${cveLink}&nbsp;`;
      cveLineBreaks += `${cveLink}</br>`;
    });
  }

  return { cveSpaced, cveLineBreaks };
}

function dateFromDateTimeString(dateTimeString: string) {
  return dateTimeString.substr(0, 10);
}

function groupVulns(vulns) {
  const result = {};
  let uniqueCount = 0;
  let pathsCount = 0;

  if (vulns && Array.isArray(vulns)) {
    vulns.map((vuln) => {
      if (!result[vuln.id]) {
        result[vuln.id] = { list: [vuln], metadata: metadataForVuln(vuln) };
        pathsCount++;
        uniqueCount++;
      } else {
        result[vuln.id].list.push(vuln);
        pathsCount++;
      }
    });
  }

  return {
    vulnerabilities: result,
    vulnerabilitiesUniqueCount: uniqueCount,
    vulnerabilitiesPathsCount: pathsCount,
  };
}

async function compileTemplate(
  fileName: fs.PathLike,
): Promise<HandlebarsTemplateDelegate> {
  const fileContent = fs.readFileSync(fileName, { encoding: 'utf8' });
  return Handlebars.compile(fileContent);
}

async function registerPeerPartial(
  templatePath: string,
  name: string,
): Promise<void> {
  const dir = path.dirname(templatePath);
  const base = path.basename(templatePath, '.hbs');
  const file = path.join(dir, `${base}.${name}.hbs`);
  if (fs.existsSync(file)) {
    const template = await compileTemplate(file);
    Handlebars.registerPartial(name, template);
  }
}

function isModernTemplate(templatePath: string): boolean {
  return path.basename(templatePath).startsWith('modernized-sca-report');