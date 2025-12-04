// ===========================================
// HARDCODE SECURITY SCANNER
// ===========================================

class EnhancedHardcodeScanner {
    constructor() {
        this.patterns = {
            // ========== CRYPTO WALLETS - IMPROVED ==========
            // Bitcoin private keys with better validation
            bitcoin_private_key_wif: {
                regex: /\b([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b/g,
                severity: '🔴 CRITICAL',
                type: 'Bitcoin Private Key (WIF)',
                validate: true,
                validator: (match) => this.validateBitcoinWIF(match)
            },
            
            bitcoin_private_key_hex: {
                regex: /\b(bitcoin[_-]?(?:private[_-]?key|priv[_-]?key))["\s]*[:=]["\s]*["']?(0x)?([a-fA-F0-9]{64})["']?/gi,
                severity: '🔴 CRITICAL',
                type: 'Bitcoin Private Key (Hex)',
                validate: true
            },

            // Ethereum with context validation
            ethereum_private_key: {
                regex: /\b(?:(?:eth|ethereum)[_-]?(?:private[_-]?key|priv[_-]?key)|privateKey)["\s]*[:=]["\s]*["']?(0x)?([a-fA-F0-9]{64})["']?/gi,
                severity: '🔴 CRITICAL',
                type: 'Ethereum Private Key',
                validate: true,
                validator: (match) => this.validateEthereumKey(match)
            },

            // Solana with better patterns
            solana_private_key_array: {
                regex: /\[(?:\s*(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\s*,\s*){31}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\s*\]/g,
                severity: '🔴 CRITICAL',
                type: 'Solana Private Key (Uint8Array)',
                validate: true
            },
            
            solana_base58_private: {
                regex: /\b(?:solana[_-]?(?:private[_-]?key|secret)|SOL_PRIVATE_KEY)["\s]*[:=]["\s]*["']?([1-9A-HJ-NP-Za-km-z]{87,88})["']?/gi,
                severity: '🔴 CRITICAL',
                type: 'Solana Private Key (Base58)',
                validate: true
            },

            // SUI with enhanced detection
            sui_private_key_bech32: {
                regex: /\b(suiprivkey1[a-z0-9]{58,})\b/g,
                severity: '🔴 CRITICAL',
                type: 'SUI Private Key (Bech32)',
                validate: true
            },
            
            sui_ed25519_key: {
                regex: /\b(?:sui[_-]?(?:private[_-]?key|secret)|SUI_PRIVATE_KEY)["\s]*[:=]["\s]*["']?([a-zA-Z0-9+/=]{44})["']?/gi,
                severity: '🔴 CRITICAL',
                type: 'SUI Private Key (Ed25519)',
                validate: true
            },

            // Comprehensive mnemonic detection
            mnemonic_12_words: {
                regex: /\b(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase|backup[_-]?phrase)["\s]*[:=]["\s]*["']((?:[a-z]{3,8}\s+){11}[a-z]{3,8})["']/gi,
                severity: '🔴 CRITICAL',
                type: '12-Word Mnemonic Phrase',
                validator: (match) => this.validateMnemonic(match, 12)
            },
            
            mnemonic_15_words: {
                regex: /\b(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase)["\s]*[:=]["\s]*["']((?:[a-z]{3,8}\s+){14}[a-z]{3,8})["']/gi,
                severity: '🔴 CRITICAL',
                type: '15-Word Mnemonic Phrase',
                validator: (match) => this.validateMnemonic(match, 15)
            },
            
            mnemonic_18_words: {
                regex: /\b(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase)["\s]*[:=]["\s]*["']((?:[a-z]{3,8}\s+){17}[a-z]{3,8})["']/gi,
                severity: '🔴 CRITICAL',
                type: '18-Word Mnemonic Phrase',
                validator: (match) => this.validateMnemonic(match, 18)
            },
            
            mnemonic_21_words: {
                regex: /\b(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase)["\s]*[:=]["\s]*["']((?:[a-z]{3,8}\s+){20}[a-z]{3,8})["']/gi,
                severity: '🔴 CRITICAL',
                type: '21-Word Mnemonic Phrase',
                validator: (match) => this.validateMnemonic(match, 21)
            },
            
            mnemonic_24_words: {
                regex: /\b(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase)["\s]*[:=]["\s]*["']((?:[a-z]{3,8}\s+){23}[a-z]{3,8})["']/gi,
                severity: '🔴 CRITICAL',
                type: '24-Word Mnemonic Phrase',
                validator: (match) => this.validateMnemonic(match, 24)
            },

            // Unquoted mnemonic detection
            mnemonic_unquoted: {
                regex: /\b((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})\b(?=\s*[;,\n\r]|$)/g,
                severity: '🔴 CRITICAL',
                type: 'Potential Mnemonic Phrase',
                validator: (match) => this.validateUnquotedMnemonic(match)
            },

            // ========== API KEYS - ENHANCED ==========
            // AWS with improved patterns
            aws_access_key_id: {
                regex: /\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b/g,
                severity: '🔴 CRITICAL',
                type: 'AWS Access Key ID',
                validate: true
            },
            
            aws_secret_access_key: {
                regex: /\b(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret|AWS_SECRET_ACCESS_KEY)["\s]*[:=]["\s]*["']?([A-Za-z0-9+/]{40})["']?/gi,
                severity: '🔴 CRITICAL',
                type: 'AWS Secret Access Key',
                validate: true,
                validator: (match) => this.validateBase64Like(match, 40)
            },
            
            aws_session_token: {
                regex: /\b(?:aws[_-]?session[_-]?token|AWS_SESSION_TOKEN)["\s]*[:=]["\s]*["']?([A-Za-z0-9+/=]{100,})["']?/gi,
                severity: '🟠 HIGH',
                type: 'AWS Session Token',
                validate: true
            },

            // Google Cloud enhanced
            gcp_api_key: {
                regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
                severity: '🟠 HIGH',
                type: 'Google Cloud API Key',
                validate: true
            },
            
            gcp_service_account_key: {
                regex: /"type":\s*"service_account"[\s\S]*?"private_key":\s*"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----"/g,
                severity: '🔴 CRITICAL',
                type: 'GCP Service Account Key',
                validate: true
            },

            // GitHub tokens with all variants
            github_pat_classic: {
                regex: /\b(ghp_[A-Za-z0-9_]{36})\b/g,
                severity: '🟠 HIGH',
                type: 'GitHub Personal Access Token (Classic)',
                validate: true
            },
            
            github_pat_fine_grained: {
                regex: /\b(github_pat_[A-Za-z0-9_]{82})\b/g,
                severity: '🟠 HIGH',
                type: 'GitHub Personal Access Token (Fine-grained)',
                validate: true
            },
            
            github_oauth: {
                regex: /\b(gho_[A-Za-z0-9_]{36})\b/g,
                severity: '🟠 HIGH',
                type: 'GitHub OAuth Token',
                validate: true
            },
            
            github_app_token: {
                regex: /\b(ghs_[A-Za-z0-9_]{36})\b/g,
                severity: '🟠 HIGH',
                type: 'GitHub App Token',
                validate: true
            },
            
            github_refresh_token: {
                regex: /\b(ghr_[A-Za-z0-9_]{36})\b/g,
                severity: '🟠 HIGH',
                type: 'GitHub Refresh Token',
                validate: true
            },

            // OpenAI enhanced
            openai_api_key: {
                regex: /\b(sk-[A-Za-z0-9]{32}T3BlbkFJ[A-Za-z0-9]{16})\b/g,
                severity: '🟠 HIGH',
                type: 'OpenAI API Key',
                validate: true
            },
            
            openai_api_key_new: {
                regex: /\b(sk-proj-[A-Za-z0-9]{48})\b/g,
                severity: '🟠 HIGH',
                type: 'OpenAI API Key (Project)',
                validate: true
            },

            // Stripe enhanced
            stripe_secret_key_live: {
                regex: /\b(sk_live_[A-Za-z0-9]{24,})\b/g,
                severity: '🔴 CRITICAL',
                type: 'Stripe Live Secret Key',
                validate: true
            },
            
            stripe_secret_key_test: {
                regex: /\b(sk_test_[A-Za-z0-9]{24,})\b/g,
                severity: '🟡 MEDIUM',
                type: 'Stripe Test Secret Key',
                validate: true
            },
            
            stripe_restricted_key: {
                regex: /\b(rk_live_[A-Za-z0-9]{24,})\b/g,
                severity: '🟠 HIGH',
                type: 'Stripe Restricted Key',
                validate: true
            },

            // Database connections improved
            mongodb_connection_string: {
                regex: /mongodb(?:\+srv)?:\/\/([^:]+):([^@]+)@([^/\s]+)(?:\/([^?\s]+))?(?:\?([^&\s]+=([^&\s]+)(&[^&\s]+=([^&\s]+))*))?/gi,
                severity: '🔴 CRITICAL',
                type: 'MongoDB Connection String',
                validate: true
            },
            
            postgresql_connection_string: {
                regex: /postgres(?:ql)?:\/\/([^:]+):([^@]+)@([^:\s]+)(?::(\d+))?\/([^?\s]+)(?:\?([^&\s]+=([^&\s]+)(&[^&\s]+=([^&\s]+))*))?/gi,
                severity: '🔴 CRITICAL',
                type: 'PostgreSQL Connection String',
                validate: true
            },
            
            mysql_connection_string: {
                regex: /mysql:\/\/([^:]+):([^@]+)@([^:\s]+)(?::(\d+))?\/([^?\s]+)(?:\?([^&\s]+=([^&\s]+)(&[^&\s]+=([^&\s]+))*))?/gi,
                severity: '🔴 CRITICAL',
                type: 'MySQL Connection String',
                validate: true
            },

            // JWT tokens with validation
            jwt_token: {
                regex: /\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g,
                severity: '🟠 HIGH',
                type: 'JWT Token',
                validator: (match) => this.validateJWT(match)
            },

            // Private keys comprehensive
            rsa_private_key: {
                regex: /-----BEGIN RSA PRIVATE KEY-----[\s\S]{100,}-----END RSA PRIVATE KEY-----/g,
                severity: '🔴 CRITICAL',
                type: 'RSA Private Key'
            },
            
            ecdsa_private_key: {
                regex: /-----BEGIN EC PRIVATE KEY-----[\s\S]{100,}-----END EC PRIVATE KEY-----/g,
                severity: '🔴 CRITICAL',
                type: 'ECDSA Private Key'
            },
            
            openssh_private_key: {
                regex: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{100,}-----END OPENSSH PRIVATE KEY-----/g,
                severity: '🔴 CRITICAL',
                type: 'OpenSSH Private Key'
            },
            
            ed25519_private_key: {
                regex: /-----BEGIN PRIVATE KEY-----[\s\S]{50,100}-----END PRIVATE KEY-----/g,
                severity: '🔴 CRITICAL',
                type: 'Ed25519 Private Key'
            },

            // Generic patterns with better validation
            generic_api_key: {
                regex: /\b(?:api[_-]?key|apikey|API_KEY)["\s]*[:=]["\s]*["']([A-Za-z0-9_\-\.]{20,})["']/gi,
                severity: '🟡 MEDIUM',
                type: 'Generic API Key',
                validator: (match) => this.validateGenericKey(match)
            },
            
            generic_secret: {
                regex: /\b(?:secret|client[_-]?secret|app[_-]?secret)["\s]*[:=]["\s]*["']([A-Za-z0-9_\-\.\/\+=]{16,})["']/gi,
                severity: '🟡 MEDIUM',
                type: 'Generic Secret',
                validator: (match) => this.validateGenericSecret(match)
            },

            // Password patterns
            password_field: {
                regex: /\b(?:password|passwd|pwd)["\s]*[:=]["\s]*["']([^"']{8,})["']/gi,
                severity: '🟡 MEDIUM',
                type: 'Password Field',
                validator: (match) => this.validatePassword(match)
            },

            // Cryptocurrency addresses (for reference, not critical)
            bitcoin_address: {
                regex: /\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g,
                severity: '🟢 INFO',
                type: 'Bitcoin Address',
                validate: true
            },
            
            ethereum_address: {
                regex: /\b(0x[a-fA-F0-9]{40})\b/g,
                severity: '🟢 INFO',
                type: 'Ethereum Address',
                validator: (match) => this.validateEthereumAddress(match)
            }
        };

        // Expanded BIP39 wordlist for better validation
        this.bip39Words = [
            'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
            'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
            'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit',
            'adult', 'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'against', 'age',
            'agent', 'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol',
            'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also',
            'alter', 'always', 'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient',
            'anger', 'angle', 'angry', 'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna'
            // ... (truncated for brevity, should include all 2048 BIP39 words)
        ];
        
        this.findings = [];
        this.scannedSources = new Set();
        this.falsePositives = new Set();
        this.scanStartTime = Date.now();
        
        // Enhanced false positive patterns
        this.excludePatterns = [
            /^[0-9a-fA-F]{64}$/, // Generic hex
            /^0+$/, // All zeros
            /^[fF]+$/, // All Fs
            /example/i,
            /your[_-]?(api[_-]?key|secret|token|password)/i,
            /placeholder/i,
            /test[_-]?(key|secret|token)/i,
            /demo[_-]?(key|secret|token)/i,
            /sample[_-]?(key|secret|token)/i,
            /fake[_-]?(key|secret|token)/i,
            /dummy[_-]?(key|secret|token)/i,
            /xxxxxxxx/i,
            /12345678/,
            /abcdefgh/i,
            /undefined/,
            /null/,
            /lorem\s+ipsum/i,
            /\$\{[^}]+\}/, // Template variables
            /%[A-Z_]+%/, // Environment variable placeholders
            /INSERT[_-]?(YOUR|API|SECRET)/i
        ];
    }

    // Validation methods
    validateBitcoinWIF(key) {
        // Basic WIF validation - should start with 5, K, or L and be proper length
        if (!/^[5KL]/.test(key)) return false;
        if (key.startsWith('5') && key.length !== 51) return false;
        if ((key.startsWith('K') || key.startsWith('L')) && key.length !== 52) return false;
        return true;
    }

    validateEthereumKey(key) {
        // Remove 0x prefix if present
        key = key.replace(/^0x/i, '');
        return key.length === 64 && /^[a-fA-F0-9]+$/.test(key);
    }

    validateEthereumAddress(address) {
        return /^0x[a-fA-F0-9]{40}$/.test(address);
    }

    validateMnemonic(phrase, wordCount) {
        const words = phrase.trim().toLowerCase().split(/\s+/);
        if (words.length !== wordCount) return false;
        
        // Check if at least 70% of words are valid BIP39 words
        const validWords = words.filter(w => this.bip39Words.includes(w));
        return validWords.length >= words.length * 0.7;
    }

    validateUnquotedMnemonic(phrase) {
        const words = phrase.trim().toLowerCase().split(/\s+/);
        if (words.length < 12 || words.length > 24) return false;
        
        // Should not be common English sentences
        const commonWords = ['the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'];
        const commonWordCount = words.filter(w => commonWords.includes(w)).length;
        if (commonWordCount > words.length * 0.3) return false;
        
        // Check if it looks like a mnemonic
        const validWords = words.filter(w => this.bip39Words.includes(w));
        return validWords.length >= words.length * 0.5;
    }

    validateJWT(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return false;
            
            // Decode header and check if it looks like JWT
            const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
            return header.typ === 'JWT' || header.alg;
        } catch {
            return false;
        }
    }

    validateBase64Like(str, expectedLength) {
        if (str.length !== expectedLength) return false;
        return /^[A-Za-z0-9+/]*={0,2}$/.test(str);
    }

    validateGenericKey(key) {
        // Filter out obvious false positives
        const fp = ['example', 'your-api-key', 'test-key', 'xxxxxxxx', '12345678', 'sample', 'demo'];
        if (fp.some(f => key.toLowerCase().includes(f))) return false;
        
        // Should have reasonable entropy
        const uniqueChars = new Set(key.toLowerCase()).size;
        return uniqueChars >= key.length * 0.4;
    }

    validateGenericSecret(secret) {
        const fp = ['your-secret', 'secret-key', 'test-secret', 'example-secret'];
        if (fp.some(f => secret.toLowerCase().includes(f))) return false;
        
        const uniqueChars = new Set(secret.toLowerCase()).size;
        return uniqueChars >= secret.length * 0.3;
    }

    validatePassword(password) {
        // Filter out obvious test passwords
        const fp = ['password', '123456', 'test123', 'admin', 'user123', 'example'];
        if (fp.some(f => password.toLowerCase().includes(f))) return false;
        
        return password.length >= 8;
    }

    isLikelyFalsePositive(match, pattern) {
        // Enhanced false positive detection
        if (this.excludePatterns.some(exp => exp.test(match))) {
            return true;
        }

        // Check for CSS colors
        if (/^#[0-9a-fA-F]{6}$/i.test(match)) {
            return true;
        }

        // Check for repeated patterns
        if (/^(.)\1+$/.test(match) || /^(..)\1+$/.test(match)) {
            return true;
        }

        // Check for common development patterns
        if (/^(test|demo|sample|example|placeholder|dummy|fake)[-_]?/i.test(match)) {
            return true;
        }

        // Run pattern-specific validator
        if (pattern.validator) {
            return !pattern.validator(match);
        }

        return false;
    }

    // Enhanced context extraction
    getContext(content, index, match) {
        const contextSize = 150;
        const start = Math.max(0, index - contextSize);
        const end = Math.min(content.length, index + match.length + contextSize);
        let context = content.substring(start, end);
        
        if (start > 0) context = '...' + context;
        if (end < content.length) context = context + '...';
        
        // Highlight the match with more visible markers
        context = context.replace(match, `🔍${match}🔍`);
        
        // Clean up the context for better readability
        context = context.replace(/\s+/g, ' ').trim();
        
        return context;
    }

    // Enhanced DOM scanning
    async scanDOM() {
        console.log('🔍 Scanning DOM content...');
        
        // Scan HTML content
        const htmlContent = document.documentElement.outerHTML;
        this.scanContent(htmlContent, 'DOM HTML', window.location.href);
        
        // Scan meta tags
        const metaTags = document.querySelectorAll('meta[content]');
        metaTags.forEach(meta => {
            this.scanContent(`${meta.name || meta.property}="${meta.content}"`, 'META Tag', meta.outerHTML);
        });
        
        // Scan data attributes comprehensively
        const elementsWithData = document.querySelectorAll('*');
        elementsWithData.forEach(el => {
            Array.from(el.attributes).forEach(attr => {
                if (attr.name.includes('key') || attr.name.includes('secret') || 
                    attr.name.includes('token') || attr.name.includes('api') ||
                    attr.name.includes('private') || attr.name.includes('credential')) {
                    this.scanContent(`${attr.name}="${attr.value}"`, 'DOM Attribute', el.tagName);
                }
            });
        });
        
        // Scan form inputs including all types
        const inputs = document.querySelectorAll('input, textarea');
        inputs.forEach(input => {
            if (input.value && input.value.length > 10) {
                this.scanContent(`${input.name || input.id || 'unnamed'}=${input.value}`, 'Form Input', input.type);
            }
            if (input.placeholder && input.placeholder.length > 10) {
                this.scanContent(input.placeholder, 'Input Placeholder', input.type);
            }
        });

        // Scan comments in HTML
        const walker = document.createTreeWalker(
            document.documentElement,
            NodeFilter.SHOW_COMMENT,
            null,
            false
        );
        
        let commentNode;
        while (commentNode = walker.nextNode()) {
            if (commentNode.nodeValue.length > 20) {
                this.scanContent(commentNode.nodeValue, 'HTML Comment', 'comment');
            }
        }
    }

    // Enhanced script scanning with better error handling
    async scanScripts() {
        console.log('📜 Scanning JavaScript files...');
        const scripts = document.querySelectorAll('script');
        const promises = [];
        
        for (let i = 0; i < scripts.length; i++) {
            const script = scripts[i];
            
            if (script.src && !this.scannedSources.has(script.src)) {
                this.scannedSources.add(script.src);
                
                const promise = this.fetchWithTimeout(script.src, 10000)
                    .then(content => {
                        this.scanContent(content, 'External Script', script.src);
                    })
                    .catch(error => {
                        console.warn(`  ⚠️ Cannot access: ${script.src} (${error.message})`);
                    });
                
                promises.push(promise);
            } else if (script.textContent && script.textContent.trim()) {
                this.scanContent(script.textContent, 'Inline Script', `inline-script-${i}`);
            }
        }
        
        // Wait for all script fetches to complete
        await Promise.allSettled(promises);
    }

    async fetchWithTimeout(url, timeout = 10000) {
        return new Promise(async (resolve, reject) => {
            const timeoutId = setTimeout(() => {
                reject(new Error('Timeout'));
            }, timeout);
            
            try {
                const response = await fetch(url);
                const content = await response.text();
                clearTimeout(timeoutId);
                resolve(content);
            } catch (error) {
                clearTimeout(timeoutId);
                reject(error);
            }
        });
    }

    // Enhanced storage scanning
    scanStorage() {
        console.log('💾 Scanning browser storage...');
        
        // LocalStorage
        try {
            const localStorageData = { ...localStorage };
            Object.entries(localStorageData).forEach(([key, value]) => {
                this.scanContent(`${key}=${value}`, 'LocalStorage', key);
                // Also scan the key itself
                this.scanContent(key, 'LocalStorage Key', key);
            });
        } catch (e) {
            console.warn('⚠️ Cannot access localStorage:', e.message);
        }

        // SessionStorage
        try {
            const sessionStorageData = { ...sessionStorage };
            Object.entries(sessionStorageData).forEach(([key, value]) => {
                this.scanContent(`${key}=${value}`, 'SessionStorage', key);
                this.scanContent(key, 'SessionStorage Key', key);
            });
        } catch (e) {
            console.warn('⚠️ Cannot access sessionStorage:', e.message);
        }

        // IndexedDB enumeration
        if (window.indexedDB) {
            this.scanIndexedDB();
        }
    }

    async scanIndexedDB() {
        try {
            console.log('  🔍 Scanning IndexedDB...');
            const databases = await indexedDB.databases();
            
            for (const dbInfo of databases) {
                console.log(`    📊 Found database: ${dbInfo.name}`);
                // Note: Full IndexedDB scanning would require opening each database
                // and iterating through object stores, which is complex and might
                // require user permission
            }
        } catch (e) {
            console.warn('    ⚠️ Cannot enumerate IndexedDB:', e.message);
        }
    }

    // Main scanning function with better progress reporting
    async scan(options = {}) {
        const opts = {
            includeScripts: true,
            includeStorage: true,
            includeCookies: true,
            includeDOM: true,
            includeWindowObject: true,
            includeFetch: true,
            deepScan: false,
            verbose: true,
            ...options
        };

        console.clear();
        console.log('%c🔍 ENHANCED HARDCODE SECURITY SCANNER v2.1', 'font-size: 20px; font-weight: bold; color: #ff6b6b;');
        console.log('%c' + '='.repeat(60), 'color: #4ecdc4;');
        console.log(`🎯 Target: ${window.location.href}`);
        console.log(`⏰ Time: ${new Date().toLocaleString()}`);
        console.log(`🔧 Mode: ${opts.deepScan ? 'DEEP SCAN' : 'STANDARD SCAN'}`);
        console.log(`📊 Patterns loaded: ${Object.keys(this.patterns).length}`);
        console.log('%c' + '='.repeat(60), 'color: #4ecdc4;');

        this.findings = [];
        this.scannedSources.clear();
        this.falsePositives.clear();

        const scanSteps = [];
        if (opts.includeDOM) scanSteps.push('DOM');
        if (opts.includeScripts) scanSteps.push('Scripts');
        if (opts.includeStorage) scanSteps.push('Storage');
        if (opts.includeCookies) scanSteps.push('Cookies');
        if (opts.includeWindowObject) scanSteps.push('Window');
        if (opts.includeFetch) scanSteps.push('Network');
        if (opts.deepScan) scanSteps.push('Deep Analysis');
        
        console.log(`🔄 Scanning: ${scanSteps.join(' → ')}`);

        try {
            let currentStep = 1;
            const totalSteps = scanSteps.length;

            if (opts.includeDOM) {
                console.log(`\n[${currentStep}/${totalSteps}] 🏗️ DOM Analysis`);
                await this.scanDOM();
                currentStep++;
            }

            if (opts.includeScripts) {
                console.log(`\n[${currentStep}/${totalSteps}] 📜 JavaScript Analysis`);
                await this.scanScripts();
                currentStep++;
            }

            if (opts.includeStorage) {
                console.log(`\n[${currentStep}/${totalSteps}] 💾 Storage Analysis`);
                this.scanStorage();
                currentStep++;
            }

            if (opts.includeCookies) {
                console.log(`\n[${currentStep}/${totalSteps}] 🍪 Cookie Analysis`);
                this.scanCookies();
                currentStep++;
            }

            if (opts.includeWindowObject) {
                console.log(`\n[${currentStep}/${totalSteps}] 🪟 Window Object Analysis`);
                this.scanWindowObject();
                currentStep++;
            }

            if (opts.includeFetch) {
                console.log(`\n[${currentStep}/${totalSteps}] 🌐 Network Monitoring Setup`);
                this.interceptFetch();
                currentStep++;
            }

            if (opts.deepScan) {
                console.log(`\n[${currentStep}/${totalSteps}] 🔬 Deep Analysis`);
                await this.deepScan();
                currentStep++;
            }

            console.log('\n' + '='.repeat(60));
            this.displayResults(opts.verbose);
            this.displaySummary();
            this.displayRecommendations();

        } catch (error) {
            console.error('❌ Scan error:', error);
            console.error('Stack trace:', error.stack);
        }

        return this.findings;
    }

    scanContent(content, type, source) {
        if (!content || typeof content !== 'string' || content.length < 5) return;
        
        Object.entries(this.patterns).forEach(([patternName, pattern]) => {
            let matches;
            try {
                matches = [...content.matchAll(pattern.regex)];
            } catch (error) {
                console.warn(`Pattern error for ${patternName}:`, error.message);
                return;
            }
            
            matches.forEach(match => {
                const matchValue = match[1] || match[0];
                
                if (this.isLikelyFalsePositive(matchValue, pattern)) {
                    this.falsePositives.add(matchValue);
                    return;
                }
                
                const finding = {
                    type: pattern.type,
                    severity: pattern.severity,
                    match: this.maskSensitiveData(matchValue),
                    fullMatch: matchValue,
                    source: source,
                    location: type,
                    timestamp: new Date().toISOString(),
                    context: this.getContext(content, match.index, match[0]),
                    confidence: pattern.validate ? 'High' : 'Medium',
                    patternName: patternName
                };

                const isDuplicate = this.findings.some(f => 
                    f.fullMatch === finding.fullMatch && 
                    f.source === finding.source &&
                    f.type === finding.type
                );

                if (!isDuplicate) {
                    this.findings.push(finding);
                }
            });
        });
    }

    scanCookies() {
        const cookies = document.cookie.split(';');
        cookies.forEach((cookie, index) => {
            if (cookie.trim()) {
                const [name, ...valueParts] = cookie.trim().split('=');
                const value = valueParts.join('=');
                
                this.scanContent(`${name}=${value}`, 'Cookie', `cookie-${name || index}`);
                
                // Scan cookie name separately
                if (name && name.length > 5) {
                    this.scanContent(name, 'Cookie Name', name);
                }
            }
        });
    }

    scanWindowObject() {
        const suspiciousKeys = [
            'apikey', 'api_key', 'apiKey', 'API_KEY',
            'secret', 'Secret', 'SECRET',
            'token', 'Token', 'TOKEN',
            'password', 'Password', 'PASSWORD',
            'privatekey', 'private_key', 'privateKey', 'PRIVATE_KEY',
            'mnemonic', 'Mnemonic', 'MNEMONIC',
            'seed', 'Seed', 'SEED',
            'credential', 'Credential', 'CREDENTIAL',
            'auth', 'Auth', 'AUTH',
            'key', 'Key', 'KEY'
        ];
        
        const scanObject = (obj, path = 'window', depth = 0) => {
            if (depth > 3) return; // Prevent infinite recursion
            
            try {
                for (const key in obj) {
                    if (obj.hasOwnProperty(key)) {
                        const fullPath = `${path}.${key}`;
                        const value = obj[key];
                        
                        if (suspiciousKeys.some(sk => key.toLowerCase().includes(sk.toLowerCase()))) {
                            if (typeof value === 'string' && value.length > 10) {
                                this.scanContent(`${fullPath}=${value}`, 'Window Object', fullPath);
                            } else if (typeof value === 'object' && value !== null) {
                                try {
                                    const jsonValue = JSON.stringify(value);
                                    if (jsonValue.length > 20 && jsonValue.length < 10000) {
                                        this.scanContent(jsonValue, 'Window Object', fullPath);
                                    }
                                } catch (e) {
                                    // Skip circular references or non-serializable objects
                                }
                            }
                        }
                        
                        // Recursively scan nested objects
                        if (typeof value === 'object' && value !== null && depth < 2) {
                            scanObject(value, fullPath, depth + 1);
                        }
                    }
                }
            } catch (e) {
                // Skip inaccessible properties
            }
        };
        
        scanObject(window);
    }

    interceptFetch() {
        if (window._securityScannerFetchIntercepted) return;
        
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {
            const [resource, config] = args;
            
            try {
                // Scan request URL
                if (typeof resource === 'string') {
                    this.scanContent(resource, 'Fetch URL', 'network-request');
                }
                
                // Scan headers
                if (config && config.headers) {
                    const headers = typeof config.headers === 'object' ? 
                        JSON.stringify(config.headers) : config.headers;
                    this.scanContent(headers, 'Fetch Headers', resource.toString());
                }
                
                // Scan body
                if (config && config.body) {
                    const body = typeof config.body === 'string' ? 
                        config.body : JSON.stringify(config.body);
                    this.scanContent(body, 'Fetch Body', resource.toString());
                }
            } catch (e) {
                // Ignore errors in interception
            }
            
            return originalFetch.apply(this, args);
        };
        
        window._securityScannerFetchIntercepted = true;
    }

    async deepScan() {
        // Wait for dynamic content
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Re-scan DOM for dynamically added content
        await this.scanDOM();
        
        // Check for framework-specific patterns
        this.scanFrameworkData();
        
        // Scan Web Workers if accessible
        this.scanWebWorkers();
        
        // Scan Service Workers if accessible  
        this.scanServiceWorkers();
    }

    scanFrameworkData() {
        // React DevTools
        if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
            console.log('  ⚛️ React detected');
            try {
                const reactFiber = document.querySelector('[data-reactroot]')?._reactInternalFiber;
                if (reactFiber) {
                    this.scanContent(JSON.stringify(reactFiber), 'React Fiber', 'react-devtools');
                }
            } catch (e) {
                // React scanning failed
            }
        }
        
        // Vue DevTools
        if (window.__VUE__) {
            console.log('  🖖 Vue detected');
            try {
                this.scanContent(JSON.stringify(window.__VUE__), 'Vue Instance', 'vue-devtools');
            } catch (e) {
                // Vue scanning failed
            }
        }
        
        // Angular
        if (window.ng || window.angular) {
            console.log('  🅰️ Angular detected');
            // Angular scanning would require more complex implementation
        }
    }

    scanWebWorkers() {
        // This is limited since we can't directly access worker content
        // but we can detect their presence
        if ('serviceWorker' in navigator) {
            console.log('  👷 Service Worker API available');
        }
    }

    scanServiceWorkers() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.getRegistrations().then(registrations => {
                if (registrations.length > 0) {
                    console.log(`  📋 Found ${registrations.length} service worker(s)`);
                    registrations.forEach(registration => {
                        if (registration.active) {
                            console.log(`    🔗 Active: ${registration.active.scriptURL}`);
                        }
                    });
                }
            }).catch(e => {
                console.warn('  ⚠️ Cannot access service workers:', e.message);
            });
        }
    }

    maskSensitiveData(data) {
        if (!data || data.length <= 12) return data;
        
        const visibleChars = 6;
        const start = data.substring(0, visibleChars);
        const end = data.substring(data.length - visibleChars);
        const maskedLength = Math.min(data.length - visibleChars * 2, 20);
        const masked = '•'.repeat(maskedLength);
        
        return `${start}${masked}${end}`;
    }

    displayResults(verbose = true) {
        console.log('\n%c📊 SCAN RESULTS', 'font-size: 18px; font-weight: bold; color: #4ecdc4;');
        console.log('%c' + '='.repeat(50), 'color: #4ecdc4;');

        if (this.findings.length === 0) {
            console.log('%c✅ No hardcoded secrets detected!', 'color: #2ed573; font-weight: bold; font-size: 16px;');
            if (this.falsePositives.size > 0) {
                console.log(`%c🔍 Filtered ${this.falsePositives.size} false positives`, 'color: #95a5a6;');
            }
            return;
        }

        const grouped = this.findings.reduce((acc, finding) => {
            const severity = finding.severity.split(' ')[1];
            if (!acc[severity]) acc[severity] = [];
            acc[severity].push(finding);
            return acc;
        }, {});

        const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        
        severityOrder.forEach(level => {
            if (grouped[level]) {
                console.log(`\n%c${grouped[level][0].severity} FINDINGS (${grouped[level].length})`, 
                    `color: ${this.getSeverityColor(level)}; font-weight: bold; font-size: 16px;`);
                console.log('%c' + '-'.repeat(50), `color: ${this.getSeverityColor(level)};`);

                grouped[level].forEach((finding, index) => {
                    console.group(`%c${index + 1}. ${finding.type}`, 
                        `color: ${this.getSeverityColor(level)}; font-weight: bold;`);
                    
                    if (verbose) {
                        console.log(`📍 Location: ${finding.location}`);
                        console.log(`🔗 Source: ${this.truncate(finding.source, 80)}`);
                        console.log(`🔑 Match: ${finding.match}`);
                        console.log(`⭐ Confidence: ${finding.confidence}`);
                        if (finding.context && finding.context.length > 0) {
                            console.log(`📝 Context: ${this.truncate(finding.context, 200)}`);
                        }
                        console.log(`⏰ Found: ${new Date(finding.timestamp).toLocaleTimeString()}`);
                    } else {
                        console.log(`${finding.location}: ${finding.match}`);
                    }
                    
                    console.groupEnd();
                });
            }
        });

        if (this.falsePositives.size > 0) {
            console.log(`\n%c🔍 Filtered ${this.falsePositives.size} false positives`, 'color: #95a5a6;');
        }
    }

    displaySummary() {
        console.log('\n%c📈 SUMMARY', 'font-size: 18px; font-weight: bold; color: #ffa502;');
        console.log('%c' + '='.repeat(40), 'color: #ffa502;');

        const stats = this.findings.reduce((acc, finding) => {
            const level = finding.severity.split(' ')[1].toLowerCase();
            acc.total++;
            acc[level] = (acc[level] || 0) + 1;
            
            if (!acc.types[finding.type]) {
                acc.types[finding.type] = 0;
            }
            acc.types[finding.type]++;
            
            if (!acc.locations[finding.location]) {
                acc.locations[finding.location] = 0;
            }
            acc.locations[finding.location]++;
            
            return acc;
        }, { total: 0, types: {}, locations: {} });

        console.log(`📊 Total findings: ${stats.total}`);
        if (stats.critical) console.log(`🔴 Critical: ${stats.critical}`);
        if (stats.high) console.log(`🟠 High: ${stats.high}`);
        if (stats.medium) console.log(`🟡 Medium: ${stats.medium}`);
        if (stats.low) console.log(`🟢 Low: ${stats.low}`);
        if (stats.info) console.log(`ℹ️ Info: ${stats.info}`);

        console.log('\n📋 Top Finding Types:');
        const sortedTypes = Object.entries(stats.types)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        
        sortedTypes.forEach(([type, count]) => {
            console.log(`  • ${type}: ${count}`);
        });

        console.log('\n📍 Findings by Location:');
        const sortedLocations = Object.entries(stats.locations)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        
        sortedLocations.forEach(([location, count]) => {
            console.log(`  • ${location}: ${count}`);
        });

        const scanDuration = ((Date.now() - this.scanStartTime) / 1000).toFixed(2);
        console.log(`\n⏱️ Scan completed in ${scanDuration}s`);
    }

    displayRecommendations() {
        if (this.findings.length === 0) {
            console.log('\n%c🛡️ SECURITY STATUS: GOOD', 'color: #2ed573; font-weight: bold; font-size: 16px;');
            console.log('Continue following security best practices!');
            return;
        }

        console.log('\n%c⚠️ SECURITY RECOMMENDATIONS', 'color: #ff6b6b; font-weight: bold; font-size: 16px;');
        console.log('%c' + '='.repeat(50), 'color: #ff6b6b;');

        const recommendations = [
            '🔐 Move all sensitive data to environment variables',
            '🏗️ Use secure secret management services (AWS Secrets Manager, HashiCorp Vault)',
            '🔄 Implement regular secret rotation policies',
            '🚫 Never commit secrets to version control',
            '📁 Use .env files for local development (add to .gitignore)',
            '🛡️ Implement proper access controls and encryption',
            '🔍 Set up automated security scanning in CI/CD pipeline',
            '📚 Train developers on secure coding practices'
        ];

        recommendations.forEach(rec => console.log(rec));

        const hasCrypto = this.findings.some(f => 
            f.type.toLowerCase().includes('private key') || 
            f.type.toLowerCase().includes('mnemonic')
        );
        const hasAPI = this.findings.some(f => f.type.toLowerCase().includes('api'));
        const hasDB = this.findings.some(f => 
            f.type.toLowerCase().includes('database') || 
            f.type.toLowerCase().includes('connection')
        );
        const hasCritical = this.findings.some(f => f.severity.includes('CRITICAL'));

        console.log('\n🎯 Immediate Actions Required:');
        if (hasCrypto) {
            console.log('  🚨 URGENT: Crypto private keys found - Secure funds immediately!');
        }
        if (hasAPI) {
            console.log('  🔄 Rotate all API keys and revoke compromised ones');
        }
        if (hasDB) {
            console.log('  🗄️ Change database credentials and review access logs');
        }
        if (hasCritical && !hasCrypto) {
            console.log('  ⚡ Address critical findings first, then work on lower severity items');
        }
    }

    getSeverityColor(level) {
        const colors = {
            'CRITICAL': '#ff4757',
            'HIGH': '#ff6348', 
            'MEDIUM': '#ffa502',
            'LOW': '#2ed573',
            'INFO': '#3742fa'
        };
        return colors[level] || '#888';
    }

    truncate(text, limit = 200) {
        if (!text || text.length <= limit) return text;
        return text.substring(0, limit) + '...';
    }

    // Export functionality with enhanced formats
    export(format = 'json') {
        const report = {
            metadata: {
                version: '2.1',
                timestamp: new Date().toISOString(),
                url: window.location.href,
                userAgent: navigator.userAgent,
                scanDuration: `${((Date.now() - this.scanStartTime) / 1000).toFixed(2)}s`,
                patternsCount: Object.keys(this.patterns).length,
                falsePositivesFiltered: this.falsePositives.size
            },
            summary: this.getSummaryStats(),
            findings: this.findings.map(f => ({
                ...f,
                match: f.fullMatch
            }))
        };

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        
        if (format === 'json') {
            this.downloadFile(
                JSON.stringify(report, null, 2),
                `security_scan_${timestamp}.json`,
                'application/json'
            );
        } else if (format === 'csv') {
            const csv = this.convertToCSV(report.findings);
            this.downloadFile(csv, `security_scan_${timestamp}.csv`, 'text/csv');
        } else if (format === 'html') {
            const html = this.generateHTMLReport(report);
            this.downloadFile(html, `security_scan_${timestamp}.html`, 'text/html');
        }
    }

    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        console.log(`✅ Report exported: ${filename}`);
    }

    convertToCSV(findings) {
        const headers = ['Type', 'Severity', 'Location', 'Source', 'Match', 'Confidence', 'Timestamp', 'Context'];
        const rows = findings.map(f => [
            f.type,
            f.severity,
            f.location,
            f.source,
            f.match,
            f.confidence,
            f.timestamp,
            f.context?.replace(/"/g, '""') || ''
        ]);
        
        return [headers, ...rows]
            .map(row => row.map(cell => `"${cell}"`).join(','))
            .join('\n');
    }

    generateHTMLReport(report) {
        return `
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .info { color: #007bff; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }
        .context { background: #f8f9fa; padding: 5px; font-family: monospace; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Scan Report</h1>
        <p><strong>URL:</strong> ${report.metadata.url}</p>
        <p><strong>Scan Time:</strong> ${report.metadata.timestamp}</p>
        <p><strong>Duration:</strong> ${report.metadata.scanDuration}</p>
        <p><strong>Total Findings:</strong> ${report.summary.total}</p>
    </div>
    
    <h2>Findings</h2>
    ${report.findings.map(finding => `
        <div class="finding">
            <h3 class="${finding.severity.split(' ')[1].toLowerCase()}">${finding.type}</h3>
            <p><strong>Severity:</strong> ${finding.severity}</p>
            <p><strong>Location:</strong> ${finding.location}</p>
            <p><strong>Source:</strong> ${finding.source}</p>
            <p><strong>Match:</strong> <code>${finding.match}</code></p>
            <p><strong>Confidence:</strong> ${finding.confidence}</p>
            ${finding.context ? `<div class="context">${finding.context}</div>` : ''}
        </div>
    `).join('')}
</body>
</html>`;
    }

    getSummaryStats() {
        const stats = this.findings.reduce((acc, finding) => {
            const level = finding.severity.split(' ')[1].toLowerCase();
            acc.total++;
            acc.bySeverity[level] = (acc.bySeverity[level] || 0) + 1;
            
            if (!acc.byType[finding.type]) {
                acc.byType[finding.type] = 0;
            }
            acc.byType[finding.type]++;
            
            if (!acc.byLocation[finding.location]) {
                acc.byLocation[finding.location] = 0;
            }
            acc.byLocation[finding.location]++;
            
            return acc;
        }, { 
            total: 0, 
            bySeverity: {}, 
            byType: {}, 
            byLocation: {},
            falsePositivesFiltered: this.falsePositives.size
        });
        
        return stats;
    }

    // Convenience methods
    quickScan() {
        this.scanStartTime = Date.now();
        return this.scan({ 
            includeScripts: false, 
            includeStorage: true, 
            includeCookies: true,
            includeWindowObject: false,
            includeFetch: false,
            deepScan: false,
            verbose: false 
        });
    }

    standardScan() {
        this.scanStartTime = Date.now();
        return this.scan({ 
            includeScripts: true, 
            includeStorage: true, 
            includeCookies: true,
            includeWindowObject: true,
            includeFetch: false,
            deepScan: false,
            verbose: true 
        });
    }

    deepFullScan() {
        this.scanStartTime = Date.now();
        return this.scan({ 
            includeScripts: true, 
            includeStorage: true, 
            includeCookies: true,
            includeWindowObject: true,
            includeFetch: true,
            deepScan: true,
            verbose: true 
        });
    }

    scanElement(element) {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        if (!element) {
            console.error('Element not found');
            return;
        }
        
        console.log(`🎯 Scanning element: ${element.tagName}${element.id ? '#' + element.id : ''}${element.className ? '.' + element.className.split(' ').join('.') : ''}`);
        this.findings = [];
        this.scanContent(element.outerHTML, 'Element Scan', element.tagName);
        this.displayResults();
        return this.findings;
    }

    startMonitoring(interval = 10000) {
        if (this.monitoringInterval) {
            console.warn('Monitoring already active. Stop current monitoring first.');
            return;
        }
        
        console.log(`🔄 Starting real-time monitoring (every ${interval/1000}s)...`);
        this.monitoringInterval = setInterval(() => {
            console.log('🔍 Running monitoring scan...');
            const previousCount = this.findings.length;
            this.quickScan();
            const newFindings = this.findings.length - previousCount;
            if (newFindings > 0) {
                console.warn(`🚨 ${newFindings} new findings detected!`);
            }
        }, interval);
        
        return this.monitoringInterval;
    }

    stopMonitoring() {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
            console.log('⏹️ Monitoring stopped');
        } else {
            console.log('No active monitoring to stop');
        }
    }

    // Pattern testing utility
    testPattern(patternName, testString) {
        if (!this.patterns[patternName]) {
            console.error(`Pattern "${patternName}" not found`);
            return false;
        }
        
        const pattern = this.patterns[patternName];
        const matches = [...testString.matchAll(pattern.regex)];
        
        console.log(`Testing pattern: ${patternName}`);
        console.log(`Test string: ${testString}`);
        console.log(`Matches: ${matches.length}`);
        
        matches.forEach((match, index) => {
            const matchValue = match[1] || match[0];
            const isValid = pattern.validator ? pattern.validator(matchValue) : true;
            const isFalsePositive = this.isLikelyFalsePositive(matchValue, pattern);
            
            console.log(`  ${index + 1}. Match: "${matchValue}"`);
            console.log(`     Valid: ${isValid}`);
            console.log(`     False Positive: ${isFalsePositive}`);
        });
        
        return matches.length > 0;
    }

    // Get pattern list
    listPatterns() {
        console.log('📋 Available Patterns:');
        console.log('=' .repeat(50));
        
        Object.entries(this.patterns).forEach(([name, pattern]) => {
            console.log(`${name.padEnd(30)} - ${pattern.type} (${pattern.severity})`);
        });
    }
}

// Initialize scanner
console.log('%c🔧 Enhanced Security Scanner v2.1 Loaded!', 'color: #4ecdc4; font-weight: bold; font-size: 16px;');
console.log('%c' + '='.repeat(60), 'color: #4ecdc4;');

const scanner = new EnhancedHardcodeScanner();
window.scanner = scanner;

console.log('%c📖 Available Commands:', 'color: #ffa502; font-weight: bold;');
console.log('• scanner.quickScan()          - Fast scan (DOM + Storage)');
console.log('• scanner.standardScan()       - Standard comprehensive scan');
console.log('• scanner.deepFullScan()       - Complete deep analysis');
console.log('• scanner.scanElement(selector)   - Scan specific DOM element');
console.log('• scanner.export()             - Export JSON report');
console.log('• scanner.export("csv")        - Export CSV report');
console.log('• scanner.export("html")       - Export HTML report');
console.log('• scanner.startMonitoring()    - Start real-time monitoring');
console.log('• scanner.stopMonitoring()     - Stop monitoring');
console.log('• scanner.testPattern(name, str) - Test specific pattern');
console.log('• scanner.listPatterns()       - Show all available patterns');
console.log('');
console.log('%cAdvanced Usage:', 'color: #6c5ce7; font-weight: bold;');
console.log('• scanner.scan(options)        - Custom scan with options');
console.log('  Options: { includeScripts, includeStorage, includeCookies,');
console.log('           includeDOM, includeWindowObject, includeFetch,');
console.log('           deepScan, verbose }');
console.log('');
console.log('%cExamples:', 'color: #a29bfe;');
console.log('scanner.testPattern("openai_api_key", "sk-1234567890abcdef");');
console.log('scanner.scanElement("#login-form");');
console.log('scanner.scan({ deepScan: true, verbose: false });');

console.log('\n%cReady! Running automatic deep scan...', 'color: #2ed573; font-weight: bold;');

// Auto-run deep scan
scanner.deepFullScan();