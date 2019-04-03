# estafette-extension-npm-audit
This extension allows you to audit npm packages

## Development
Before committing your changes run:

```
go test ./...
go mod tidy
go mod vendor
```
## Usage
You can add one stage to your `.estafette.yaml` like this:
```
stages:
  audit:
    image: extensions/npm-audit:stable
    action: audit
    level: low
    dev-level: none
    workspace: estafette
    channels:
    - '#builds-${ESTAFETTE_LABEL_TEAM}'
```

### Action
For now the only supported action is `audit`

### Level
This is the level you set to check for the vulnerabilities in the `dependencies` from your `package.json`.

Possible values are:
 - `none`
 - `low`
 - `moderate`
 - `high`
 - `critical`

With level `none` you disable the check completely.

#### Example
Let's say you want to check only for vulnerabilities that have a priority level higher or equal to **moderate**.

Then if audit finds vulnerabilities with level lower than moderate, this extension will send a Slack message to [channels](#channels) with the npm audit report. And your build will continue.

If audit finds vulnerabilities with level higher or equal to moderate, then your build will break and you will still receive a Slack message.

If audit doesn't find any vulnerabilities, then you get no Slack message and your build will continue.

### Dev-level
This is the same as [Level](#level). But for the `devDependencies` from your `package.json`

### Workspace
The Slack workspace you use.

### Channels
A list with the Slack channels you want to send the reports with the result from npm audit.
