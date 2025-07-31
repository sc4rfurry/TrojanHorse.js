/**
 * High-Performance Streaming Processor
 * 
 * Handles large threat intelligence feeds with memory-efficient streaming,
 * chunking, and parallel processing capabilities.
 */

import { Transform, Readable, Writable } from 'stream';
import { pipeline } from 'stream/promises';
import { Worker } from 'worker_threads';
import { EventEmitter } from 'events';
import { ThreatIndicator, ThreatFeedResult } from '../types';

interface StreamingConfig {
  chunkSize: number;
  maxConcurrency: number;
  bufferSize: number;
  workerPoolSize: number;
  memoryThreshold: number; // bytes
  enableCompression: boolean;
  retryAttempts: number;
  timeout: number;
}

interface ChunkProcessor {
  process(chunk: Buffer): Promise<ThreatIndicator[]>;
}

interface ProcessingStats {
  itemsProcessed: number;
  chunksProcessed: number;
  errorsEncountered: number;
  processingTime: number;
  memoryUsage: NodeJS.MemoryUsage;
  throughput: number; // items per second
}

export class StreamingProcessor extends EventEmitter {
  private config: StreamingConfig;
  private workerPool: Worker[] = [];
  private processingQueue: Array<{ chunk: Buffer; resolve: Function; reject: Function }> = [];
  private activeWorkers: Set<Worker> = new Set();
  private stats: ProcessingStats;
  private startTime: number = 0;

  constructor(config: Partial<StreamingConfig> = {}) {
    super();
    
    this.config = {
      chunkSize: 1024 * 1024, // 1MB chunks
      maxConcurrency: require('os').cpus().length,
      bufferSize: 10 * 1024 * 1024, // 10MB buffer
      workerPoolSize: require('os').cpus().length,
      memoryThreshold: 500 * 1024 * 1024, // 500MB threshold
      enableCompression: true,
      retryAttempts: 3,
      timeout: 30000,
      ...config
    };

    this.stats = this.initializeStats();
    this.initializeWorkerPool();
  }

  private initializeStats(): ProcessingStats {
    return {
      itemsProcessed: 0,
      chunksProcessed: 0,
      errorsEncountered: 0,
      processingTime: 0,
      memoryUsage: process.memoryUsage(),
      throughput: 0
    };
  }

  private async initializeWorkerPool(): Promise<void> {
    for (let i = 0; i < this.config.workerPoolSize; i++) {
      const worker = new Worker(`
        const { parentPort } = require('worker_threads');
        
        // Worker script for processing threat data chunks
        parentPort.on('message', async ({ chunkData, processorType, config }) => {
          try {
            let indicators = [];
            
            switch (processorType) {
              case 'csv':
                indicators = await processCSVChunk(chunkData, config);
                break;
              case 'json':
                indicators = await processJSONChunk(chunkData, config);
                break;
              case 'xml':
                indicators = await processXMLChunk(chunkData, config);
                break;
              default:
                throw new Error('Unsupported processor type');
            }
            
            parentPort.postMessage({ success: true, indicators });
          } catch (error) {
            parentPort.postMessage({ success: false, error: error.message });
          }
        });
        
        async function processCSVChunk(csvData, config) {
          const lines = csvData.toString().split('\\n');
          const indicators = [];
          
          for (const line of lines) {
            if (line.trim() && !line.startsWith('#')) {
              try {
                const indicator = parseCSVLine(line, config);
                if (indicator) indicators.push(indicator);
              } catch (error) {
                // Skip malformed lines
                continue;
              }
            }
          }
          
          return indicators;
        }
        
        function parseCSVLine(line, config) {
          const columns = line.split(',').map(col => 
            col.replace(/^"/, '').replace(/"$/, '').trim()
          );
          
          if (columns.length < 6) return null;
          
          const [id, dateAdded, url, urlStatus, lastOnline, threat] = columns;
          
          try {
            const urlObj = new URL(url);
            return {
              type: 'url',
              value: url,
              confidence: urlStatus === 'online' ? 0.8 : 0.6,
              firstSeen: new Date(dateAdded),
              lastSeen: new Date(lastOnline || dateAdded),
              source: 'StreamProcessor',
              tags: [threat.toLowerCase()],
              severity: threat.toLowerCase().includes('malware') ? 'high' : 'medium'
            };
          } catch (urlError) {
            return null;
          }
        }
        
        async function processJSONChunk(jsonData, config) {
          const indicators = [];
          const lines = jsonData.toString().split('\\n');
          
          for (const line of lines) {
            if (line.trim()) {
              try {
                const item = JSON.parse(line);
                const indicator = convertJSONToIndicator(item, config);
                if (indicator) indicators.push(indicator);
              } catch (error) {
                continue;
              }
            }
          }
          
          return indicators;
        }
        
        function convertJSONToIndicator(item, config) {
          // Generic JSON to ThreatIndicator conversion
          return {
            type: item.type || 'unknown',
            value: item.value || item.indicator,
            confidence: item.confidence || 0.5,
            firstSeen: new Date(item.first_seen || Date.now()),
            lastSeen: new Date(item.last_seen || Date.now()),
            source: item.source || 'StreamProcessor',
            tags: Array.isArray(item.tags) ? item.tags : [],
            severity: item.severity || 'medium'
          };
        }
        
        async function processXMLChunk(xmlData, config) {
          // Basic XML processing - in production, use a proper XML parser
          const indicators = [];
          const xmlString = xmlData.toString();
          
          // Simple regex-based XML parsing for demo
          const itemMatches = xmlString.match(/<item[^>]*>.*?<\\/item>/gs);
          
          if (itemMatches) {
            for (const match of itemMatches) {
              try {
                const indicator = parseXMLItem(match, config);
                if (indicator) indicators.push(indicator);
              } catch (error) {
                continue;
              }
            }
          }
          
          return indicators;
        }
        
        function parseXMLItem(xmlItem, config) {
          const getValue = (tag) => {
            const match = xmlItem.match(new RegExp(\`<\${tag}[^>]*>(.*?)</\${tag}>\`, 's'));
            return match ? match[1].trim() : '';
          };
          
          return {
            type: getValue('type') || 'unknown',
            value: getValue('value') || getValue('indicator'),
            confidence: parseFloat(getValue('confidence')) || 0.5,
            firstSeen: new Date(getValue('first_seen') || Date.now()),
            lastSeen: new Date(getValue('last_seen') || Date.now()),
            source: getValue('source') || 'StreamProcessor',
            tags: getValue('tags').split(',').filter(Boolean),
            severity: getValue('severity') || 'medium'
          };
        }
      `, { eval: true });

      worker.on('error', (error) => {
        this.emit('worker:error', error);
        this.replaceWorker(worker);
      });

      this.workerPool.push(worker);
    }
  }

  private replaceWorker(faultyWorker: Worker): void {
    const index = this.workerPool.indexOf(faultyWorker);
    if (index !== -1) {
      faultyWorker.terminate();
      this.workerPool.splice(index, 1);
      
      // Create replacement worker
      this.initializeWorkerPool();
    }
  }

  /**
   * Process a stream of threat data with high performance
   */
  public async processStream(
    inputStream: Readable,
    processor: ChunkProcessor,
    options: {
      processorType: 'csv' | 'json' | 'xml';
      onProgress?: (stats: ProcessingStats) => void;
      onChunkProcessed?: (indicators: ThreatIndicator[]) => void;
    }
  ): Promise<ThreatFeedResult> {
    this.startTime = Date.now();
    this.stats = this.initializeStats();

    const allIndicators: ThreatIndicator[] = [];
    const chunks: Buffer[] = [];
    let currentChunk = Buffer.alloc(0);

    try {
      // Capture config values for use in transform functions
      const chunkSize = this.config.chunkSize;
      const bufferSize = this.config.bufferSize;
      
      // Create chunking transform stream
      const chunkingStream = new Transform({
        objectMode: false,
        highWaterMark: bufferSize,
        
        transform(chunk: Buffer, encoding, callback) {
          currentChunk = Buffer.concat([currentChunk, chunk]);
          
          // Split into processable chunks
          while (currentChunk.length >= chunkSize) {
            const processChunk = currentChunk.slice(0, chunkSize);
            currentChunk = currentChunk.slice(chunkSize);
            this.push(processChunk);
          }
          
          callback();
        },
        
        flush(callback) {
          // Process remaining data
          if (currentChunk.length > 0) {
            this.push(currentChunk);
          }
          callback();
        }
      });

      // Create processing stream
      const processingStream = new Writable({
        objectMode: false,
        highWaterMark: this.config.bufferSize,
        
        write: async (chunk: Buffer, encoding, callback) => {
          try {
            await this.monitorMemoryUsage();
            
            const indicators = await this.processChunkWithWorker(
              chunk, 
              options.processorType
            );
            
            allIndicators.push(...indicators);
            this.stats.chunksProcessed++;
            this.stats.itemsProcessed += indicators.length;
            
            // Emit progress
            if (options.onProgress) {
              this.updateStats();
              options.onProgress(this.stats);
            }
            
            if (options.onChunkProcessed) {
              options.onChunkProcessed(indicators);
            }
            
            this.emit('chunk:processed', {
              chunkSize: chunk.length,
              indicatorsFound: indicators.length,
              totalProcessed: this.stats.itemsProcessed
            });
            
            callback();
          } catch (error) {
            this.stats.errorsEncountered++;
            this.emit('error', error);
            callback(error instanceof Error ? error : new Error(String(error)));
          }
        }
      });

      // Process the stream
      await pipeline(inputStream, chunkingStream, processingStream);

      this.updateStats();

      return {
        source: 'StreamingProcessor',
        timestamp: new Date(),
        indicators: allIndicators,
        metadata: {
          totalCount: allIndicators.length,
          processingStats: {
            startTime: new Date(),
            endTime: new Date(),
            itemsProcessed: this.stats.itemsProcessed || 0,
            errorsEncountered: this.stats.errorsEncountered || 0,
            totalSize: 0,
            avgProcessingTimeMs: 0,
            memoryUsageMB: process.memoryUsage().heapUsed / 1024 / 1024
          },
          streamingConfig: this.config
        }
      };

    } catch (error) {
      this.emit('error', error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`Streaming processing failed: ${errorMessage}`);
    }
  }

  private async processChunkWithWorker(chunk: Buffer, processorType: string): Promise<ThreatIndicator[]> {
    return new Promise((resolve, reject) => {
      const availableWorker = this.getAvailableWorker();
      
      if (!availableWorker) {
        // Queue the work if no workers available
        this.processingQueue.push({ chunk, resolve, reject });
        return;
      }

      this.processWithWorker(availableWorker, chunk, processorType, resolve, reject);
    });
  }

  private getAvailableWorker(): Worker | null {
    for (const worker of this.workerPool) {
      if (!this.activeWorkers.has(worker)) {
        return worker;
      }
    }
    return null;
  }

  private processWithWorker(
    worker: Worker, 
    chunk: Buffer, 
    processorType: string,
    resolve: Function, 
    reject: Function
  ): void {
    this.activeWorkers.add(worker);

    const timeout = setTimeout(() => {
      this.activeWorkers.delete(worker);
      reject(new Error('Worker processing timeout'));
    }, this.config.timeout);

    const messageHandler = (result: any) => {
      clearTimeout(timeout);
      this.activeWorkers.delete(worker);
      worker.off('message', messageHandler);

      if (result.success) {
        resolve(result.indicators);
      } else {
        reject(new Error(result.error));
      }

      // Process queued work
      this.processQueue();
    };

    worker.on('message', messageHandler);
    worker.postMessage({
      chunkData: chunk,
      processorType,
      config: this.config
    });
  }

  private processQueue(): void {
    if (this.processingQueue.length === 0) {
      return;
    }

    const availableWorker = this.getAvailableWorker();
    if (!availableWorker) {
      return;
    }

    const { chunk, resolve, reject } = this.processingQueue.shift()!;
    this.processWithWorker(availableWorker, chunk, 'csv', resolve, reject);
  }

  private async monitorMemoryUsage(): Promise<void> {
    const memUsage = process.memoryUsage();
    
    if (memUsage.heapUsed > this.config.memoryThreshold) {
      this.emit('memory:warning', {
        current: memUsage.heapUsed,
        threshold: this.config.memoryThreshold,
        percentage: (memUsage.heapUsed / this.config.memoryThreshold) * 100
      });

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      // Wait a bit to allow GC
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  private updateStats(): void {
    const now = Date.now();
    this.stats.processingTime = now - this.startTime;
    this.stats.memoryUsage = process.memoryUsage();
    
    if (this.stats.processingTime > 0) {
      this.stats.throughput = (this.stats.itemsProcessed / this.stats.processingTime) * 1000;
    }
  }

  /**
   * Creates a chunking stream for large data processing
   */
  public createLargeDataStream(filePath: string): Transform {
    let currentChunk = Buffer.alloc(0);
    
    // Capture config values for use in transform functions
    const chunkSize = this.config.chunkSize;
    const bufferSize = this.config.bufferSize;
    
    // Create chunking transform stream
    const chunkingStream = new Transform({
      objectMode: false,
      highWaterMark: bufferSize,
      
      transform(chunk: Buffer, encoding, callback) {
        currentChunk = Buffer.concat([currentChunk, chunk]);
        
        // Split into processable chunks
        while (currentChunk.length >= chunkSize) {
          const processChunk = currentChunk.slice(0, chunkSize);
          currentChunk = currentChunk.slice(chunkSize);
          this.push(processChunk);
        }
        
        callback();
      },
      
      flush(callback) {
        // Process remaining data
        if (currentChunk.length > 0) {
          this.push(currentChunk);
        }
        callback();
      }
    });

    return chunkingStream;
  }

  private createHttpStream(url: string): Readable {
    const https = require('https');
    const http = require('http');
    
    const client = url.startsWith('https:') ? https : http;
    
    return new Readable({
      read() {
        // @ts-ignore - Temporary workaround for stream _started property
        if (!this._started) {
          // @ts-ignore
          this._started = true;
          
          const request = client.get(url, (response: any) => {
            response.on('data', (chunk: Buffer) => {
              this.push(chunk);
            });
            
            response.on('end', () => {
              this.push(null);
            });
            
            response.on('error', (error: Error) => {
              this.emit('error', error);
            });
          });
          
          request.on('error', (error: Error) => {
            this.emit('error', error);
          });
        }
      }
    });
  }

  private createFileStream(filePath: string): Readable {
    const fs = require('fs');
    return fs.createReadStream(filePath, {
      highWaterMark: this.config.bufferSize
    });
  }

  /**
   * Batch process multiple data sources concurrently
   */
  public async batchProcess(
    sources: Array<{ source: string | Buffer | Readable; type: 'csv' | 'json' | 'xml' }>,
    options: {
      maxConcurrency?: number;
      onSourceComplete?: (source: string, result: ThreatFeedResult) => void;
    } = {}
  ): Promise<ThreatFeedResult[]> {
    const maxConcurrency = options.maxConcurrency || this.config.maxConcurrency;
    const results: ThreatFeedResult[] = [];
    const processing: Promise<ThreatFeedResult>[] = [];

    for (const { source, type } of sources) {
      const processPromise = this.processStream(
        // @ts-ignore - Temporary workaround for source type
        this.createLargeDataStream(source),
        this.createSimpleProcessor(),
        {
          processorType: type,
          onProgress: (stats) => {
            this.emit('batch:progress', { source, stats });
          }
        }
      ).then(result => {
        if (options.onSourceComplete) {
          options.onSourceComplete(source.toString(), result);
        }
        return result;
      });

      processing.push(processPromise);

      // Limit concurrency
      if (processing.length >= maxConcurrency) {
        const completed = await Promise.race(processing);
        results.push(completed);
        processing.splice(processing.indexOf(Promise.resolve(completed)), 1);
      }
    }

    // Wait for remaining processes
    const remaining = await Promise.all(processing);
    results.push(...remaining);

    return results;
  }

  private createSimpleProcessor(): ChunkProcessor {
    return {
      async process(chunk: Buffer): Promise<ThreatIndicator[]> {
        // This is handled by workers, just return empty array
        return [];
      }
    };
  }

  /**
   * Get processing statistics
   */
  public getStats(): ProcessingStats {
    this.updateStats();
    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  public resetStats(): void {
    this.stats = this.initializeStats();
    this.startTime = Date.now();
  }

  /**
   * Gracefully shutdown the processor
   */
  public async shutdown(): Promise<void> {
    this.emit('shutdown:start');

    // Wait for active work to complete
    while (this.activeWorkers.size > 0) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    // Terminate all workers
    await Promise.all(
      this.workerPool.map(worker => worker.terminate())
    );

    this.workerPool = [];
    this.processingQueue = [];
    this.activeWorkers.clear();

    this.emit('shutdown:complete');
  }
}

/**
 * Utility function to create optimized streaming processor
 */
export function createOptimizedProcessor(options: {
  type: 'high-throughput' | 'low-memory' | 'balanced';
  customConfig?: Partial<StreamingConfig>;
} = { type: 'balanced' }): StreamingProcessor {
  let config: Partial<StreamingConfig>;

  switch (options.type) {
  case 'high-throughput':
    config = {
      chunkSize: 2 * 1024 * 1024, // 2MB chunks
      maxConcurrency: require('os').cpus().length * 2,
      bufferSize: 50 * 1024 * 1024, // 50MB buffer
      workerPoolSize: require('os').cpus().length * 2,
      memoryThreshold: 1024 * 1024 * 1024, // 1GB threshold
      enableCompression: false, // Disabled for speed
      ...options.customConfig
    };
    break;

  case 'low-memory':
    config = {
      chunkSize: 256 * 1024, // 256KB chunks
      maxConcurrency: Math.max(2, Math.floor(require('os').cpus().length / 2)),
      bufferSize: 5 * 1024 * 1024, // 5MB buffer
      workerPoolSize: Math.max(2, Math.floor(require('os').cpus().length / 2)),
      memoryThreshold: 100 * 1024 * 1024, // 100MB threshold
      enableCompression: true,
      ...options.customConfig
    };
    break;

  default: // balanced
    config = {
      chunkSize: 1024 * 1024, // 1MB chunks
      maxConcurrency: require('os').cpus().length,
      bufferSize: 10 * 1024 * 1024, // 10MB buffer
      workerPoolSize: require('os').cpus().length,
      memoryThreshold: 500 * 1024 * 1024, // 500MB threshold
      enableCompression: true,
      ...options.customConfig
    };
  }

  return new StreamingProcessor(config);
} 