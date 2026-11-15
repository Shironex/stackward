// A tiny prompt for the captures: it reads one line, runs the stackward
// binary from bin/ with those arguments in the terminal, then prompts again.
// No real shell runs, so nothing from the machine that renders the pictures
// (user name, host name, paths) can reach them.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const bin = path.join(here, 'bin', process.platform === 'win32' ? 'stackward.exe' : 'stackward');
const prompt = '\x1b[32m$\x1b[0m ';

function ask() {
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  rl.setPrompt(prompt);
  rl.prompt();
  rl.once('line', line => {
    rl.close();
    const [cmd, ...args] = line.trim().split(/\s+/).filter(Boolean);
    if (cmd !== 'stackward') {
      if (cmd) process.stdout.write(`${cmd}: only stackward runs here\n`);
      ask();
      return;
    }
    const child = spawn(bin, args, { stdio: 'inherit' });
    child.on('exit', () => ask());
    child.on('error', err => {
      process.stdout.write(`${err.message}\n`);
      ask();
    });
  });
}

ask();
