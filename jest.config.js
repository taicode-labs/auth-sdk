module.exports = {
  transform: {
    ".ts": 'ts-jest'
  },
  testRegex: '.+\\.test\\.ts$',
  testPathIgnorePatterns: [
    "output",
    "node_modules"
  ]
}
