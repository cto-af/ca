'use strict';

/** @import * as typedoc from 'typedoc'; */
/** @type {typedoc.TypeDocOptions} */
module.exports = {
  entryPoints: ['src/index.ts'],
  out: 'docs',
  cleanOutputDir: true,
  sidebarLinks: {
    GitHub: 'https://github.com/hildjj/cto-af/ca/',
    Documentation: 'http://cto-af.github.io/ca/',
  },
  navigation: {
    includeCategories: false,
    includeGroups: false,
  },
  includeVersion: true,
  categorizeByGroup: false,
  sort: ['static-first', 'alphabetical'],
  exclude: ['**/*.spec.ts'],
};
