# Contributing to TrojanHorse.js

We welcome contributions from the cybersecurity community! This guide will help you get started.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Development Environment

1. **Fork and Clone**
```bash
git clone https://github.com/YOUR-USERNAME/TrojanHorse.js.git
cd TrojanHorse.js
```

2. **Install Dependencies**
```bash
npm install
```

3. **Build Project**
```bash
npm run build:all
```

4. **Run Tests**
```bash
npm test
```

### Development Workflow

1. **Create Feature Branch**
```bash
git checkout -b feature/your-feature-name
```

2. **Make Changes**
- Follow coding standards
- Add tests for new features
- Update documentation

3. **Test Changes**
```bash
npm test
npm run lint
npm audit
```

4. **Commit Changes**
```bash
git add .
git commit -m "feat: add new feature description"
```

5. **Push and Create PR**
```bash
git push origin feature/your-feature-name
```

## Contribution Types

### 🐛 Bug Reports
- Use GitHub Issues
- Include reproduction steps
- Provide environment details
- Attach relevant logs

### 💡 Feature Requests
- Describe the use case
- Explain the benefit
- Consider implementation impact
- Discuss with maintainers first

### 🔧 Code Contributions
- Follow coding standards
- Include tests
- Update documentation
- Consider security implications

### 📚 Documentation
- Fix typos and errors
- Improve clarity
- Add examples
- Translate content

### 🔒 Security
- Follow responsible disclosure
- Email security@trojanhorse-js.com
- Do not create public issues for vulnerabilities

## Development Standards

### Code Style

#### TypeScript
```typescript
// ✅ Good
interface ThreatIndicator {
  id: string;
  type: ThreatType;
  confidence: number;
  timestamp: Date;
}

class ThreatAnalyzer {
  private readonly config: AnalyzerConfig;

  constructor(config: AnalyzerConfig) {
    this.config = config;
  }

  public async analyze(indicator: ThreatIndicator): Promise<AnalysisResult> {
    // Implementation
  }
}
```

#### JavaScript
```javascript
// ✅ Good
const threatAnalyzer = {
  analyze: async (indicator) => {
    if (!indicator || !indicator.type) {
      throw new Error('Invalid threat indicator');
    }
    
    return {
      risk: calculateRisk(indicator),
      recommendations: getRecommendations(indicator)
    };
  }
};
```

### Testing Standards

#### Unit Tests
```javascript
describe('ThreatAnalyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new ThreatAnalyzer(mockConfig);
  });

  it('should analyze threat indicators', async () => {
    const indicator = createMockIndicator();
    const result = await analyzer.analyze(indicator);
    
    expect(result).toBeDefined();
    expect(result.risk).toBeGreaterThan(0);
  });

  it('should handle invalid input', async () => {
    await expect(analyzer.analyze(null))
      .rejects.toThrow('Invalid threat indicator');
  });
});
```

#### Integration Tests
```javascript
describe('TrojanHorse Integration', () => {
  it('should fetch real threat data', async () => {
    const trojan = new TrojanHorse({
      sources: ['urlhaus'],
      strategy: 'defensive'
    });

    const threats = await trojan.scout('example.com');
    expect(Array.isArray(threats)).toBe(true);
  });
});
```

### Documentation Standards

#### JSDoc Comments
```typescript
/**
 * Analyzes threat indicators for risk assessment
 * @param indicator - The threat indicator to analyze
 * @param options - Analysis configuration options
 * @returns Promise resolving to analysis results
 * @throws {Error} When indicator is invalid
 * @example
 * ```typescript
 * const result = await analyzer.analyze(indicator, { deep: true });
 * console.log(`Risk level: ${result.risk}`);
 * ```
 */
public async analyze(
  indicator: ThreatIndicator,
  options: AnalysisOptions = {}
): Promise<AnalysisResult>
```

#### README Updates
- Keep installation instructions current
- Add new feature documentation
- Update examples
- Maintain feature matrix

## Project Structure

```
src/
├── core/           # Core functionality
├── feeds/          # Threat intelligence feeds
├── security/       # Cryptography and security
├── correlation/    # Threat correlation engine
├── analytics/      # Analytics and reporting
├── integrations/   # SIEM and tool integrations
├── enterprise/     # Enterprise features
├── tests/          # Test utilities
├── types/          # TypeScript definitions
├── browser.ts      # Browser entry point
└── index.ts        # Main entry point
```

## Adding New Features

### New Threat Feed
1. Create feed class in `src/feeds/`
2. Implement `ThreatFeed` interface
3. Add tests in `src/tests/feeds/`
4. Update documentation
5. Add to main exports

```typescript
// src/feeds/NewFeed.ts
export class NewFeed implements ThreatFeed {
  async fetchThreatData(): Promise<ThreatData[]> {
    // Implementation
  }
}
```

### New Security Feature
1. Add to `src/security/`
2. Follow cryptographic standards
3. Add comprehensive tests
4. Security review required
5. Document security implications

### New Integration
1. Add to `src/integrations/`
2. Implement standard interface
3. Add configuration options
4. Include usage examples
5. Test with real systems

## Testing Guidelines

### Test Categories
- **Unit Tests**: Test individual functions/classes
- **Integration Tests**: Test component interactions
- **Security Tests**: Test security features
- **Performance Tests**: Test performance benchmarks
- **Browser Tests**: Test browser compatibility

### Test Commands
```bash
# All tests
npm test

# Specific test types
npm run test:unit
npm run test:integration
npm run test:security
npm run test:performance

# Coverage report
npm run test:coverage

# Watch mode
npm run test:watch
```

### Test Requirements
- **Coverage**: Minimum 80% code coverage
- **Security**: All security features must have tests
- **Performance**: Performance-critical code needs benchmarks
- **Browser**: Browser features need browser tests

## Review Process

### Pull Request Checklist
- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Security implications considered
- [ ] Performance impact assessed
- [ ] Backwards compatibility maintained

### Review Criteria
1. **Code Quality**: Clean, readable, maintainable
2. **Testing**: Adequate test coverage
3. **Security**: No security vulnerabilities
4. **Performance**: No performance regressions
5. **Documentation**: Clear and complete
6. **Compatibility**: Works across supported platforms

## Release Process

### Version Scheme
We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

### Release Checklist
- [ ] All tests passing
- [ ] Documentation updated
- [ ] Security audit completed
- [ ] Performance benchmarks run
- [ ] Changelog updated
- [ ] Version number updated

## Community

### Communication Channels
- **GitHub Discussions**: General questions and discussions
- **GitHub Issues**: Bug reports and feature requests
- **Discord**: Real-time community chat
- **Email**: security@trojanhorse-js.com for security issues

### Recognition
- Contributors are recognized in releases
- Significant contributors get commit access
- Security researchers get hall of fame recognition

## Getting Help

### For Contributors
- Read existing code and tests
- Ask questions in GitHub Discussions
- Join our Discord community
- Reach out to maintainers

### For Maintainers
- Review PRs promptly
- Provide constructive feedback
- Help new contributors
- Maintain project standards

---

**Thank you for contributing to TrojanHorse.js! Together we make the internet safer.** 🛡️