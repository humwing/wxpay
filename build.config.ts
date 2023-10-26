import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
  entries: [
    "./src/index.ts",
  ],
  rollup: {
    emitCJS: true,
  },
  externals: [/node_modules/, 'axios'],
  failOnWarn: false,
  declaration: true,
});