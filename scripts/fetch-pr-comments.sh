#!/usr/bin/env bash
set -euo pipefail

PR_NUMBER="${1:-}"

if [ -z "$PR_NUMBER" ]; then
  echo "Usage: ./scripts/fetch-pr-comments.sh <pr-number>"
  exit 1
fi

OUT_FILE="pr-comments-context.md"

{
  echo "# PR Comments Context"
  echo

  echo "## PR Info"
  gh pr view "$PR_NUMBER" --json number,title,url,author,body,baseRefName,headRefName \
    | jq -r '
      "- PR #\(.number): \(.title)\n- URL: \(.url)\n- Author: \(.author.login)\n- Base: \(.baseRefName)\n- Head: \(.headRefName)\n\n\(.body // "")"
    '

  echo
  echo "## Conversation Comments"
  gh api "repos/:owner/:repo/issues/$PR_NUMBER/comments" --paginate \
    | jq -r '.[] | "### Comment by \(.user.login)\n\n\(.body)\n"'

  echo
  echo "## Inline Review Comments"
  gh api "repos/:owner/:repo/pulls/$PR_NUMBER/comments" --paginate \
    | jq -r '.[] | "### \(.path):\(.line // .original_line // 0) by \(.user.login)\n\nComment:\n\(.body)\n\nDiff hunk:\n```diff\n\(.diff_hunk)\n```\n"'

  echo
  echo "## Reviews"
  gh api "repos/:owner/:repo/pulls/$PR_NUMBER/reviews" --paginate \
    | jq -r '.[] | "### Review by \(.user.login) - \(.state)\n\n\(.body // "")\n"'

} > "$OUT_FILE"

echo "Wrote $OUT_FILE"
