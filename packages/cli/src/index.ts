#!/usr/bin/env node
import { Command } from 'commander';
import { scanCommand } from './commands/scan';
import { reportCommand } from './commands/report';

const program = new Command();
program.name('ghsec').description('GitHub Security Configuration Checker').version('0.1.0');
program.addCommand(scanCommand);
program.addCommand(reportCommand);
program.parse();
