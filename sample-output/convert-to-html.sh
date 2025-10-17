#!/bin/sh

for f in *.md; do
  fn=$(basename -s ".md" ${f})
  echo "${fn}.md --> ${fn}.html"
  pandoc -s -o ${fn}.html ${fn}.md --css=style.css
done
