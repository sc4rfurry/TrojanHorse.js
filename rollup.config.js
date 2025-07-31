/**
 * Rollup configuration for Node.js builds of TrojanHorse.js
 * Handles Node.js built-ins properly as externals
 */

import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';
import json from '@rollup/plugin-json';

// Node.js externals (these should NOT be bundled)
const nodeExternals = [
  // Node.js built-ins
  'argon2',
  'crypto',
  'fs',
  'path',
  'os',
  'util',
  'module',
  'url',
  'node:crypto',
  'node:util',
  'node:assert',
  'events',
  'stream',
  'buffer',
  // Project dependencies that should remain external
  'crypto-js',
  'axios',
  'dexie',
  'joi',
  'commander',
  'chalk',
  'ora',
  'inquirer',
  'express',
  'helmet',
  'compression',
  'express-rate-limit',
  'cors',
  'jsonwebtoken',
  'bcryptjs',
  'winston',
  'express-validator',
  'swagger-ui-express',
  'swagger-jsdoc',
  'multer',
  'ws',
  'redis',
  'nodemailer',
  'otplib',
  'qrcode',
  'express-session',
  '@elastic/elasticsearch',
  'validator',
  'sanitize-html',
  'node-forge'
];

// Base plugins for Node.js builds
const basePlugins = [
  resolve({
    preferBuiltins: true, // Prefer Node.js built-ins
    browser: false,
    exportConditions: ['node', 'import', 'require']
  }),
  commonjs({
    include: ['node_modules/**']
  }),
  json(),
  typescript({
    tsconfig: './tsconfig.json'
  })
];

export default [
  // Node.js ES Module build
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/trojanhorse.esm.js',
      format: 'es',
      exports: 'named',
      sourcemap: true
    },
    external: [...nodeExternals, /^node:/], // Externalize Node.js modules
    plugins: basePlugins
  },

  // Node.js CommonJS build
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/trojanhorse.js',
      format: 'cjs',
      exports: 'named',
      sourcemap: true
    },
    external: [...nodeExternals, /^node:/],
    plugins: basePlugins
  },

  // Node.js UMD build (for compatibility)
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/trojanhorse.umd.js',
      format: 'umd',
      name: 'TrojanHorse',
      exports: 'named',
      sourcemap: true,
      globals: {
        'argon2': 'argon2',
        'crypto': 'crypto',
        'fs': 'fs',
        'path': 'path',
        'os': 'os',
        'util': 'util',
        'module': 'module',
        'url': 'url',
        'node:crypto': 'crypto',
        'node:util': 'util',
        'node:assert': 'assert',
        'crypto-js': 'CryptoJS',
        'axios': 'axios',
        'dexie': 'Dexie'
      }
    },
    external: [...nodeExternals, /^node:/],
    plugins: basePlugins
  },

  // Node.js Minified build
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/trojanhorse.min.js',
      format: 'umd',
      name: 'TrojanHorse',
      exports: 'named',
      sourcemap: true,
      globals: {
        'argon2': 'argon2',
        'crypto': 'crypto',
        'fs': 'fs',
        'path': 'path',
        'os': 'os',
        'util': 'util',
        'module': 'module',
        'url': 'url',
        'node:crypto': 'crypto',
        'node:util': 'util',
        'node:assert': 'assert',
        'crypto-js': 'CryptoJS',
        'axios': 'axios',
        'dexie': 'Dexie'
      }
    },
    external: [...nodeExternals, /^node:/],
    plugins: [
      ...basePlugins,
      terser({
        compress: {
          drop_console: ['log', 'info'], // Keep warn and error
          drop_debugger: true
        },
        mangle: {
          reserved: ['TrojanHorse']
        },
        format: {
          comments: false
        }
      })
    ]
  }
]; 