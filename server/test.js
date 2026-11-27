import test from 'node:test';
import assert from 'node:assert/strict';
import {validUsername,validRepoName,validRepoPath} from './src/validation.js';
test('username validation',()=>{assert.equal(validUsername('dev-user'),true);assert.equal(validUsername('x'),false)});
test('repository name validation',()=>{assert.equal(validRepoName('my_repo.js'),true);assert.equal(validRepoName('..'),false)});
test('repository path validation blocks traversal',()=>{assert.equal(validRepoPath('src/index.js'),true);assert.equal(validRepoPath('../secret'),false);assert.equal(validRepoPath('/etc/passwd'),false)});
