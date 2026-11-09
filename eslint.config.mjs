// SEC-01A: browser helper static safety rules. Broader style policy is deferred.
export default [
  {
    files: ["extenstion/*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "script",
    },
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-with": "error",
      "no-prototype-builtins": "warn",
      "no-unsafe-optional-chaining": "error",
    },
  },
];
