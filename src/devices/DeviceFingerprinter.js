const crypto = require('crypto');
const UAParser = require('ua-parser-js');

class DeviceFingerprinter {
  constructor(config) {
    this.config = config;
    this.fingerprintAlgorithms = this.initializeAlgorithms();
  }

  initializeAlgorithms() {
    return {
      // Canvas fingerprinting
      canvas: {
        enabled: true,
        weight: 0.3,
        generate: (req) => this.generateCanvasFingerprint(req)
      },

      // WebGL fingerprinting
      webgl: {
        enabled: true,
        weight: 0.25,
        generate: (req) => this.generateWebGLFingerprint(req)
      },

      // Audio fingerprinting
      audio: {
        enabled: true,
        weight: 0.15,
        generate: (req) => this.generateAudioFingerprint(req)
      },

      // Font fingerprinting
      fonts: {
        enabled: true,
        weight: 0.2,
        generate: (req) => this.generateFontFingerprint(req)
      },

      // Plugin fingerprinting
      plugins: {
        enabled: true,
        weight: 0.1,
        generate: (req) => this.generatePluginFingerprint(req)
      }
    };
  }

  async generateFingerprint(req) {
    const fingerprint = {
      id: null,
      components: {},
      confidence: 0,
      metadata: {},
      timestamp: Date.now()
    };

    try {
      // Generate basic device info from headers
      const deviceInfo = this.extractDeviceInfo(req.headers);
      fingerprint.metadata = deviceInfo;

      // Generate component fingerprints
      for (const [algorithm, config] of Object.entries(this.fingerprintAlgorithms)) {
        if (config.enabled) {
          try {
            const componentFingerprint = await config.generate(req);
            fingerprint.components[algorithm] = componentFingerprint;
          } catch (error) {
            fingerprint.components[algorithm] = { error: error.message };
          }
        }
      }

      // Generate composite fingerprint ID
      fingerprint.id = this.generateCompositeId(fingerprint.components, deviceInfo);
      
      // Calculate confidence score
      fingerprint.confidence = this.calculateConfidence(fingerprint.components);

      return fingerprint;
    } catch (error) {
      throw new Error(`Failed to generate device fingerprint: ${error.message}`);
    }
  }

  extractDeviceInfo(headers) {
    const userAgent = headers['user-agent'] || '';
    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    return {
      browser: {
        name: result.browser.name,
        version: result.browser.version,
        major: result.browser.major
      },
      engine: {
        name: result.engine.name,
        version: result.engine.version
      },
      os: {
        name: result.os.name,
        version: result.os.version
      },
      device: {
        model: result.device.model,
        type: result.device.type,
        vendor: result.device.vendor
      },
      cpu: {
        architecture: result.cpu.architecture
      },
      userAgent: userAgent,
      acceptLanguage: headers['accept-language'],
      acceptEncoding: headers['accept-encoding'],
      screenResolution: headers['x-screen-resolution'],
      colorDepth: headers['x-color-depth'],
      timezone: headers['x-timezone'],
      language: headers['x-language']
    };
  }

  generateCanvasFingerprint(req) {
    // Extract canvas fingerprint from request body or headers
    const canvasData = req.body?.canvasFingerprint || req.headers['x-canvas-fingerprint'];
    
    if (!canvasData) {
      return { error: 'Canvas fingerprint not provided' };
    }

    try {
      // Parse and validate canvas data
      const canvas = typeof canvasData === 'string' ? JSON.parse(canvasData) : canvasData;
      
      return {
        hash: crypto.createHash('sha256').update(JSON.stringify(canvas)).digest('hex'),
        data: {
          width: canvas.width,
          height: canvas.height,
          colorDepth: canvas.colorDepth,
          pixelDepth: canvas.pixelDepth,
          dataURL: canvas.dataURL ? canvas.dataURL.substring(0, 100) + '...' : null
        }
      };
    } catch (error) {
      return { error: 'Invalid canvas fingerprint data' };
    }
  }

  generateWebGLFingerprint(req) {
    const webglData = req.body?.webglFingerprint || req.headers['x-webgl-fingerprint'];
    
    if (!webglData) {
      return { error: 'WebGL fingerprint not provided' };
    }

    try {
      const webgl = typeof webglData === 'string' ? JSON.parse(webglData) : webglData;
      
      return {
        hash: crypto.createHash('sha256').update(JSON.stringify(webgl)).digest('hex'),
        data: {
          vendor: webgl.vendor,
          renderer: webgl.renderer,
          version: webgl.version,
          extensions: webgl.extensions?.length || 0,
          parameters: webgl.parameters ? Object.keys(webgl.parameters).length : 0
        }
      };
    } catch (error) {
      return { error: 'Invalid WebGL fingerprint data' };
    }
  }

  generateAudioFingerprint(req) {
    const audioData = req.body?.audioFingerprint || req.headers['x-audio-fingerprint'];
    
    if (!audioData) {
      return { error: 'Audio fingerprint not provided' };
    }

    try {
      const audio = typeof audioData === 'string' ? JSON.parse(audioData) : audioData;
      
      return {
        hash: crypto.createHash('sha256').update(JSON.stringify(audio)).digest('hex'),
        data: {
          sampleRate: audio.sampleRate,
          channelCount: audio.channelCount,
          audioContext: audio.audioContext,
          oscillator: audio.oscillator
        }
      };
    } catch (error) {
      return { error: 'Invalid audio fingerprint data' };
    }
  }

  generateFontFingerprint(req) {
    const fontData = req.body?.fontFingerprint || req.headers['x-font-fingerprint'];
    
    if (!fontData) {
      return { error: 'Font fingerprint not provided' };
    }

    try {
      const fonts = typeof fontData === 'string' ? JSON.parse(fontData) : fontData;
      
      return {
        hash: crypto.createHash('sha256').update(JSON.stringify(fonts)).digest('hex'),
        data: {
          availableFonts: fonts.availableFonts?.length || 0,
          missingFonts: fonts.missingFonts?.length || 0,
          totalFonts: (fonts.availableFonts?.length || 0) + (fonts.missingFonts?.length || 0)
        }
      };
    } catch (error) {
      return { error: 'Invalid font fingerprint data' };
    }
  }

  generatePluginFingerprint(req) {
    const pluginData = req.body?.pluginFingerprint || req.headers['x-plugin-fingerprint'];
    
    if (!pluginData) {
      return { error: 'Plugin fingerprint not provided' };
    }

    try {
      const plugins = typeof pluginData === 'string' ? JSON.parse(pluginData) : pluginData;
      
      return {
        hash: crypto.createHash('sha256').update(JSON.stringify(plugins)).digest('hex'),
        data: {
          pluginCount: plugins.length || 0,
          pluginNames: plugins.map(p => p.name).slice(0, 5) // First 5 plugin names
        }
      };
    } catch (error) {
      return { error: 'Invalid plugin fingerprint data' };
    }
  }

  generateCompositeId(components, deviceInfo) {
    // Create a composite string from all available fingerprint components
    const compositeData = {
      components: {},
      deviceInfo: {
        browser: deviceInfo.browser?.name,
        os: deviceInfo.os?.name,
        device: deviceInfo.device?.type,
        userAgent: deviceInfo.userAgent
      }
    };

    // Add component hashes
    for (const [algorithm, component] of Object.entries(components)) {
      if (component.hash) {
        compositeData.components[algorithm] = component.hash;
      }
    }

    // Generate final composite hash
    const compositeString = JSON.stringify(compositeData);
    return crypto.createHash('sha256').update(compositeString).digest('hex');
  }

  calculateConfidence(components) {
    let totalWeight = 0;
    let weightedScore = 0;

    for (const [algorithm, config] of Object.entries(this.fingerprintAlgorithms)) {
      if (config.enabled && components[algorithm] && !components[algorithm].error) {
        totalWeight += config.weight;
        weightedScore += config.weight;
      }
    }

    // Normalize confidence score (0-100)
    return totalWeight > 0 ? Math.round((weightedScore / totalWeight) * 100) : 0;
  }

  compareFingerprints(fingerprint1, fingerprint2) {
    if (!fingerprint1 || !fingerprint2) {
      return { similarity: 0, confidence: 0 };
    }

    let matchingComponents = 0;
    let totalComponents = 0;

    // Compare component hashes
    for (const algorithm of Object.keys(this.fingerprintAlgorithms)) {
      const comp1 = fingerprint1.components[algorithm];
      const comp2 = fingerprint2.components[algorithm];

      if (comp1 && comp2 && !comp1.error && !comp2.error) {
        totalComponents++;
        if (comp1.hash === comp2.hash) {
          matchingComponents++;
        }
      }
    }

    const similarity = totalComponents > 0 ? matchingComponents / totalComponents : 0;
    const confidence = Math.min(fingerprint1.confidence, fingerprint2.confidence);

    return {
      similarity: Math.round(similarity * 100),
      confidence,
      matchingComponents,
      totalComponents
    };
  }

  generateClientScript() {
    return `
      // ZTF-JS Device Fingerprinting Client Script
      (function() {
        'use strict';
        
        const ZTF = {
          canvas: null,
          webgl: null,
          audio: null,
          fonts: null,
          plugins: null
        };

        // Canvas Fingerprinting
        ZTF.generateCanvasFingerprint = function() {
          try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            canvas.width = 200;
            canvas.height = 200;
            
            // Draw some text and shapes
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('ZTF-JS Fingerprint', 2, 2);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillRect(100, 5, 80, 20);
            
            return {
              width: canvas.width,
              height: canvas.height,
              colorDepth: screen.colorDepth,
              pixelDepth: screen.pixelDepth,
              dataURL: canvas.toDataURL()
            };
          } catch (e) {
            return { error: e.message };
          }
        };

        // WebGL Fingerprinting
        ZTF.generateWebGLFingerprint = function() {
          try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            
            if (!gl) {
              return { error: 'WebGL not supported' };
            }

            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            
            return {
              vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'Unknown',
              renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'Unknown',
              version: gl.getParameter(gl.VERSION),
              extensions: gl.getSupportedExtensions(),
              parameters: {
                'MAX_TEXTURE_SIZE': gl.getParameter(gl.MAX_TEXTURE_SIZE),
                'MAX_VIEWPORT_DIMS': gl.getParameter(gl.MAX_VIEWPORT_DIMS),
                'MAX_VERTEX_UNIFORM_VECTORS': gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
                'MAX_FRAGMENT_UNIFORM_VECTORS': gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS)
              }
            };
          } catch (e) {
            return { error: e.message };
          }
        };

        // Audio Fingerprinting
        ZTF.generateAudioFingerprint = function() {
          try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const analyser = audioContext.createAnalyser();
            
            oscillator.connect(analyser);
            oscillator.type = 'triangle';
            oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
            
            return {
              sampleRate: audioContext.sampleRate,
              channelCount: audioContext.destination.channelCount,
              audioContext: audioContext.state,
              oscillator: oscillator.type
            };
          } catch (e) {
            return { error: e.message };
          }
        };

        // Font Fingerprinting
        ZTF.generateFontFingerprint = function() {
          const testString = 'mmmmmmmmmmlli';
          const testSize = '72px';
          const h = document.getElementsByTagName('body')[0];
          
          const baseFonts = ['monospace', 'sans-serif', 'serif'];
          const fontList = [
            'Arial', 'Verdana', 'Helvetica', 'Times New Roman', 'Courier New',
            'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS',
            'Trebuchet MS', 'Arial Black', 'Impact', 'Lucida Console'
          ];
          
          const availableFonts = [];
          const missingFonts = [];
          
          for (const font of fontList) {
            let matched = 0;
            for (const baseFont of baseFonts) {
              const s = document.createElement('span');
              s.style.fontSize = testSize;
              s.style.fontFamily = font + ',' + baseFont;
              s.innerHTML = testString;
              h.appendChild(s);
              
              const defaultWidth = {};
              const defaultHeight = {};
              
              for (const baseFont of baseFonts) {
                const c = document.createElement('span');
                c.style.fontSize = testSize;
                c.style.fontFamily = baseFont;
                c.innerHTML = testString;
                h.appendChild(c);
                defaultWidth[baseFont] = c.offsetWidth;
                defaultHeight[baseFont] = c.offsetHeight;
                h.removeChild(c);
              }
              
              const matched = (s.offsetWidth !== defaultWidth[baseFont] || s.offsetHeight !== defaultHeight[baseFont]);
              h.removeChild(s);
              
              if (matched) {
                availableFonts.push(font);
                break;
              }
            }
            
            if (!matched) {
              missingFonts.push(font);
            }
          }
          
          return {
            availableFonts,
            missingFonts
          };
        };

        // Plugin Fingerprinting
        ZTF.generatePluginFingerprint = function() {
          const plugins = [];
          
          if (navigator.plugins) {
            for (let i = 0; i < navigator.plugins.length; i++) {
              const plugin = navigator.plugins[i];
              plugins.push({
                name: plugin.name,
                description: plugin.description,
                filename: plugin.filename
              });
            }
          }
          
          return plugins;
        };

        // Generate complete fingerprint
        ZTF.generateFingerprint = function() {
          return {
            canvasFingerprint: ZTF.generateCanvasFingerprint(),
            webglFingerprint: ZTF.generateWebGLFingerprint(),
            audioFingerprint: ZTF.generateAudioFingerprint(),
            fontFingerprint: ZTF.generateFontFingerprint(),
            pluginFingerprint: ZTF.generatePluginFingerprint(),
            timestamp: Date.now(),
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            screenResolution: screen.width + 'x' + screen.height,
            colorDepth: screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
          };
        };

        // Expose to global scope
        window.ZTF = ZTF;
        
        console.log('ZTF-JS Device Fingerprinting loaded');
      })();
    `;
  }

  validateFingerprint(fingerprint) {
    const errors = [];

    if (!fingerprint.id) {
      errors.push('Missing fingerprint ID');
    }

    if (!fingerprint.components || Object.keys(fingerprint.components).length === 0) {
      errors.push('No fingerprint components found');
    }

    if (fingerprint.confidence < 0 || fingerprint.confidence > 100) {
      errors.push('Invalid confidence score');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }
}

module.exports = DeviceFingerprinter;
