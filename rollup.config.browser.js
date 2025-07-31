/**
 * Rollup configuration for browser builds of TrojanHorse.js
 * Handles Node.js built-ins and provides proper polyfills
 */

import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';
import replace from '@rollup/plugin-replace';
import json from '@rollup/plugin-json';
import nodePolyfills from 'rollup-plugin-polyfill-node';

// Browser-specific configuration
const browserConfig = {
  preferBuiltins: false,
  browser: true,
  exportConditions: ['browser']
};

// Define external Node.js modules that shouldn't be bundled in browser
const nodeExternals = [
  'argon2',
  'fs',
  'path',
  'os',
  'crypto',
  'util',
  'module',
  'url',
  'node:crypto',
  'node:util',
  'node:assert'
];

// Define globals for externals (browser equivalents)
const nodeGlobals = {
  'argon2': 'null', // Not available in browser
  'fs': 'null',
  'path': 'null', 
  'os': 'null',
  'crypto': 'crypto', // Use Web Crypto API
  'util': 'null',
  'module': 'null',
  'url': 'URL',
  'node:crypto': 'crypto',
  'node:util': 'null',
  'node:assert': 'null'
};

const plugins = [
  // Replace Node.js specific code for browser compatibility
  replace({
    preventAssignment: true,
    values: {
      'process.env.NODE_ENV': JSON.stringify('production'),
      'typeof process': JSON.stringify('undefined'),
      'process.versions.node': 'undefined',
      'process.versions?.node': 'undefined'
    }
  }),
  
  // Add Node.js polyfills for browser
  nodePolyfills({
    include: ['crypto', 'util', 'buffer', 'events', 'stream']
  }),
  
  // Resolve modules with browser preference
  resolve(browserConfig),
  
  // Handle CommonJS modules
  commonjs({
    include: ['node_modules/**'],
    transformMixedEsModules: true
  }),
  
  // Handle JSON imports
  json(),
  
  // TypeScript compilation for browser
  typescript({
    tsconfig: './tsconfig.browser.json',
    declaration: false,
    declarationMap: false
  })
];

export default [
  // Browser UMD build (for CDN)
  {
    input: 'src/browser.ts',
    output: {
      file: 'dist/trojanhorse.browser.umd.js',
      format: 'umd',
      name: 'TrojanHorse',
      exports: 'named',
      sourcemap: true,
      globals: nodeGlobals
    },
    external: nodeExternals,
    plugins: [...plugins]
  },
  
  // Browser UMD build (minified for CDN)
  {
    input: 'src/browser.ts',
    output: {
      file: 'dist/trojanhorse.browser.min.js',
      format: 'umd',
      name: 'TrojanHorse',
      exports: 'named',
      sourcemap: true,
      globals: nodeGlobals
    },
    external: nodeExternals,
    plugins: [
      ...plugins,
      terser({
        compress: {
          drop_console: true,
          drop_debugger: true,
          pure_funcs: ['console.log', 'console.warn']
        },
        mangle: {
          reserved: ['TrojanHorse', 'BrowserUtils']
        }
      })
    ]
  },
  
  // Browser ES Module build
  {
    input: 'src/browser.ts',
    output: {
      file: 'dist/trojanhorse.browser.esm.js',
      format: 'es',
      exports: 'named',
      sourcemap: true
    },
    external: nodeExternals,
    plugins: [...plugins]
  },
  
  // Browser IIFE build (standalone)
  {
    input: 'src/browser.ts',
    output: {
      file: 'dist/trojanhorse.browser.iife.js',
      format: 'iife',
      name: 'TrojanHorse',
      exports: 'named',
      sourcemap: true,
      globals: nodeGlobals
    },
    external: nodeExternals,
    plugins: [
      ...plugins,
      terser({
        compress: {
          drop_console: false, // Keep console for IIFE debugging
          drop_debugger: true
        }
      })
    ]
  }
]; 