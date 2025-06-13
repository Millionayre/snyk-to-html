#!/usr/bin/env node

import program = require('commander');
import debugModule = require('debug');
import fs = require('fs');
import path = require('path');
import { SnykToHtml } from './lib/snyk-to-html';

program
  .option(
    '-t, --template <path>',
    'Template location for generating the html. Defaults to template/test-report.hbs',
  )
  .option(
    '-i, --input <path>',
    'Input path from where to read the json. Defaults to stdin',
  )
  .option(
    '-o, --output <path>',
    'Output of the resulting HTML. Example: -o snyk.html. Defaults to stdout',
  )
  .option(
    '-s, --summary',
    'Generates an HTML with only the summary, instead of the details report',
  )
  .option('-d, --debug', 'Runs the CLI in debug mode')
  .option(
    '-a, --actionable-remediation',
    'Display actionable remediation info if available',
  )