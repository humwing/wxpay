import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
  entries: [
    "./src/index.ts",
  ],
  rollup: {
    emitCJS: true,
    output: {
      exports: 'named'
    }
  },
  externals: [/node_modules/, 'axios'],
  failOnWarn: false,
  declaration: true,
});