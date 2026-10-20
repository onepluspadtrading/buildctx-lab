#!/bin/sh
echo "I73754_SHELL host=$(hostname) date=$(date -u +%FT%TZ)"
node ./run2.js 2>&1
echo "I73754_SHELL_DONE rc=$?"
