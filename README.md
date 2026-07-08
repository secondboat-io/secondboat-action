# SecondBoat IaC Scan Action

Stop shipping vulnerable infrastructure. SecondBoat scans your Terraform,
CloudFormation, and more on every push — before it ever reaches your cloud.

## Usage

```yaml
steps:
  - name: Checkout repo
    uses: actions/checkout@v4

  - name: SecondBoat IaC Scan
    uses: secondboat-io/secondboat-action@v1
    with:
      api-key: ${{ secrets.SECONDBOAT_CI_KEY }}
      org-id:  ${{ secrets.SECONDBOAT_ORG_ID }}
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `api-key` | ✅ | — | Your SecondBoat CI API key |
| `org-id` | ✅ | — | Your SecondBoat organization ID |
| `api-url` | ❌ | `https://api.secondboat.io/v1/scan` | API endpoint |
| `fail-on-violation` | ❌ | `true` | Fail workflow if violations found |

## Outputs

| Output | Description |
|---|---|
| `status` | `passed`, `failed`, or `no_iac` |
| `total_failed` | Number of failed checks |

## Secrets Setup

Go to your repo → **Settings → Secrets → Actions** and add:
- `SECONDBOAT_CI_KEY`
- `SECONDBOAT_ORG_ID`
