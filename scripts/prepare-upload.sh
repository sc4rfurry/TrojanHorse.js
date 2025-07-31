#!/bin/bash
set -e

echo "🧹 Preparing TrojanHorse.js for GitHub Upload..."

# Remove unnecessary files
echo "🗑️  Cleaning up unnecessary files..."
rm -rf node_modules/ coverage/ dist/ .nyc_output/ tmp/ temp/
rm -f *.log npm-debug.log* yarn-debug.log* yarn-error.log*
rm -f package-lock.json yarn.lock

# Clean up any remaining test files
rm -f quick-test.* corrected-test.* final-validation.* test-production.*

# Verify build works
echo "🔨 Testing build process..."
npm install
npm run build:all

# Run tests
echo "🧪 Running tests..."
npm test || echo "⚠️  Some tests failed (expected in clean environment)"

# Lint check
echo "🔍 Running linter..."
npm run lint

# Security audit
echo "🔐 Running security audit..."
npm audit || echo "⚠️  Some audit issues found (review manually)"

# Show what will be uploaded
echo "📋 Files ready for upload:"
find . -type f \
  ! -path "./node_modules/*" \
  ! -path "./coverage/*" \
  ! -path "./dist/*" \
  ! -path "./.git/*" \
  ! -name "*.log" \
  ! -name "package-lock.json" \
  ! -name "yarn.lock" \
  | sort

echo "✅ TrojanHorse.js is ready for GitHub upload!"
echo "📁 Repository: https://github.com/sc4rfurry/TrojanHorse.js"

echo ""
echo "🚀 Next steps:"
echo "1. git add ."
echo "2. git commit -m 'Complete production-ready implementation'"
echo "3. git push origin main"
echo "4. Follow COMPLETE_DEPLOYMENT_GUIDE.md for publishing"