import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
  // If entries is not provided, will be automatically inferred from package.json
  entries: [
    // default
    "./src/index.ts",
    // mkdist builder transpiles file-to-file keeping original sources structure
    // {
    //   builder: "mkdist",
    //   input: "./src/package/components/",
    //   outDir: "./build/components",
    // },
  ],
  rollup: {
    inlineDependencies: true,
    output: {
      sourcemap: false,
    },
    emitCJS: true
  },
  externals: [/node_modules/, 'axios'],
  // Change outDir, default is 'dist'
  outDir: "dist",
  failOnWarn: false,
  // Generates .d.ts declaration file
  declaration: 'node16',
});