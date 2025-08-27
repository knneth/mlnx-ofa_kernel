#!/usr/bin/env bash

usage() {
    echo "Usage: $0 <upstream_issue>"
    echo ""
    echo "This script searches for commits in git log that match a given upstream_issue in metadata/*.csv files."
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message and exit."
    echo ""
    echo "Example:"
    echo "  $0 4468524"
}

if [ $# -eq 0 ]; then
    usage
    exit 1
fi

case "$1" in
    -h|--help)
        usage
        exit 0
        ;;
esac

search_issue="$1"
found=0

echo "Searching for commits with upstream_issue=$search_issue in metadata files..."

while IFS=: read -r file line; do
    subject=$(echo "$line" | grep -o 'subject=[^;]*' | cut -d= -f2)

    if [ -n "$subject" ]; then
        results=$(git log --all --grep="$subject" --pretty=format:'%h ("%s")')

        if [ -n "$results" ]; then
            echo "$results"
            found=1
        fi
    fi
done < <(grep -H "upstream_issue=$search_issue;" metadata/*.csv)

if [ $found -eq 0 ]; then
    echo "No matching commits found in git log."
fi
