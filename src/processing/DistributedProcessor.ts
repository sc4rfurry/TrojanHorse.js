/**
 * TrojanHorse.js Distributed Processing Engine
 * Enterprise-grade distributed threat analysis and processing
 */

import { EventEmitter } from 'events';
import { Worker } from 'worker_threads';
import { ThreatIndicator, ThreatFeedResult } from '../types';

// ===== PROCESSING INTERFACES =====

export interface ProcessingConfig {
  maxWorkers: number;
  minWorkers: number;
  queueSize: number;
  taskTimeout: number;
  retryAttempts: number;
  scalingStrategy: 'fixed' | 'dynamic' | 'adaptive';
}

export interface Task {
  id: string;
  type: 'threat_analysis' | 'data_processing' | 'correlation' | 'enrichment';
  priority: 'low' | 'medium' | 'high' | 'critical';
  data: any;
  createdAt: Date;
  timeout?: number;
  retries?: number;
}

export interface TaskResult {
  taskId: string;
  success: boolean;
  result?: any;
  error?: string;
  processingTime: number;
  workerId: string;
  completedAt: Date;
}

export interface WorkerPoolConfig {
  maxWorkers: number;
  minWorkers: number;
  workerScript: string;
  taskTimeout: number;
  idleTimeout: number;
  autoScale: boolean;
}

// ===== WORKER POOL =====

class WorkerPool extends EventEmitter {
  private config: WorkerPoolConfig;
  private workers: Map<string, Worker> = new Map();
  private taskQueue: Task[] = [];
  private activeTasks: Map<string, Task> = new Map();
  private workerStats: Map<string, any> = new Map();

  constructor(config: WorkerPoolConfig) {
    super();
    this.config = config;
    this.initializeWorkers();
  }

  private initializeWorkers(): void {
    for (let i = 0; i < this.config.minWorkers; i++) {
      this.createWorker();
    }
  }

  private createWorker(): string {
    const workerId = `worker_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    try {
      const worker = new Worker(this.config.workerScript, {
        workerData: { workerId }
      });

      worker.on('message', (message) => {
        this.handleWorkerMessage(workerId, message);
      });

      worker.on('error', (error) => {
        this.handleWorkerError(workerId, error);
      });

      worker.on('exit', (code) => {
        this.handleWorkerExit(workerId, code);
      });

      this.workers.set(workerId, worker);
      this.workerStats.set(workerId, {
        created: new Date(),
        tasksCompleted: 0,
        tasksInProgress: 0,
        lastActivity: new Date()
      });

      this.emit('worker_created', { workerId });
      return workerId;
      
    } catch (error) {
      this.emit('worker_creation_failed', { workerId, error });
      throw error;
    }
  }

  private handleWorkerMessage(workerId: string, message: any): void {
    const stats = this.workerStats.get(workerId);
    if (stats) {
      stats.lastActivity = new Date();
      stats.tasksInProgress--;
      stats.tasksCompleted++;
    }

    if (message.type === 'task_completed') {
      this.handleTaskCompletion(workerId, message);
    } else if (message.type === 'task_error') {
      this.handleTaskError(workerId, message);
    }

    this.processNextTask();
  }

  private handleTaskCompletion(workerId: string, message: any): void {
    const task = this.activeTasks.get(message.taskId);
    if (task) {
      const result: TaskResult = {
        taskId: message.taskId,
        success: true,
        result: message.result,
        processingTime: message.processingTime,
        workerId,
        completedAt: new Date()
      };

      this.activeTasks.delete(message.taskId);
      this.emit('task_completed', result);
    }
  }

  private handleTaskError(workerId: string, message: any): void {
    const task = this.activeTasks.get(message.taskId);
    if (task) {
      const result: TaskResult = {
        taskId: message.taskId,
        success: false,
        error: message.error,
        processingTime: message.processingTime || 0,
        workerId,
        completedAt: new Date()
      };

      this.activeTasks.delete(message.taskId);
      
      // Retry logic
      if ((task.retries || 0) < 3) {
        task.retries = (task.retries || 0) + 1;
        this.addTask(task);
      } else {
        this.emit('task_failed', result);
      }
    }
  }

  private handleWorkerError(workerId: string, error: Error): void {
    this.emit('worker_error', { workerId, error: error.message });
    this.removeWorker(workerId);
    
    // Replace failed worker if needed
    if (this.workers.size < this.config.minWorkers) {
      this.createWorker();
    }
  }

  private handleWorkerExit(workerId: string, code: number): void {
    this.emit('worker_exit', { workerId, exitCode: code });
    this.removeWorker(workerId);
  }

  private removeWorker(workerId: string): void {
    const worker = this.workers.get(workerId);
    if (worker) {
      worker.terminate();
      this.workers.delete(workerId);
      this.workerStats.delete(workerId);
    }
  }

  public addTask(task: Task): void {
    this.taskQueue.push(task);
    this.processNextTask();
  }

  private processNextTask(): void {
    if (this.taskQueue.length === 0) {
      return;
    }

    const availableWorker = this.findAvailableWorker();
    if (!availableWorker) {
      if (this.shouldScaleUp()) {
        this.scaleUp();
      }
      return;
    }

    const task = this.taskQueue.shift()!;
    this.assignTaskToWorker(task, availableWorker);
  }

  private findAvailableWorker(): string | null {
    for (const [workerId, stats] of this.workerStats) {
      if (stats.tasksInProgress < 1) {
        return workerId;
      }
    }
    return null;
  }

  private shouldScaleUp(): boolean {
    return this.workers.size < this.config.maxWorkers && 
           this.taskQueue.length > this.workers.size * 2;
  }

  private scaleUp(): void {
    if (this.workers.size < this.config.maxWorkers) {
      this.createWorker();
    }
  }

  private assignTaskToWorker(task: Task, workerId: string): void {
    const worker = this.workers.get(workerId);
    const stats = this.workerStats.get(workerId);
    
    if (worker && stats) {
      stats.tasksInProgress++;
      this.activeTasks.set(task.id, task);
      
      worker.postMessage({
        type: 'execute_task',
        task
      });

      // Set timeout for task
      setTimeout(() => {
        if (this.activeTasks.has(task.id)) {
          this.handleTaskTimeout(task.id, workerId);
        }
      }, task.timeout || this.config.taskTimeout);
    }
  }

  private handleTaskTimeout(taskId: string, workerId: string): void {
    const task = this.activeTasks.get(taskId);
    if (task) {
      this.activeTasks.delete(taskId);
      
      const result: TaskResult = {
        taskId,
        success: false,
        error: 'Task timeout',
        processingTime: task.timeout || this.config.taskTimeout,
        workerId,
        completedAt: new Date()
      };

      this.emit('task_timeout', result);
    }
  }

  public getStats(): any {
    return {
      totalWorkers: this.workers.size,
      queueSize: this.taskQueue.length,
      activeTasks: this.activeTasks.size,
      workerStats: Object.fromEntries(this.workerStats)
    };
  }

  public async shutdown(): Promise<void> {
    const shutdownPromises = Array.from(this.workers.values()).map(worker => 
      worker.terminate()
    );
    
    await Promise.all(shutdownPromises);
    this.workers.clear();
    this.workerStats.clear();
    this.activeTasks.clear();
  }
}

// ===== DISTRIBUTED PROCESSOR =====

class DistributedProcessor extends EventEmitter {
  private config: ProcessingConfig;
  private workerPool: WorkerPool;
  private taskCounter = 0;

  constructor(config: ProcessingConfig) {
    super();
    this.config = config;
    this.workerPool = new WorkerPool({
      maxWorkers: config.maxWorkers,
      minWorkers: config.minWorkers,
      workerScript: require.resolve('./threat-analysis-worker.js'),
      taskTimeout: config.taskTimeout,
      idleTimeout: 60000,
      autoScale: config.scalingStrategy !== 'fixed'
    });

    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.workerPool.on('task_completed', (result) => {
      this.emit('task_completed', result);
    });

    this.workerPool.on('task_failed', (result) => {
      this.emit('task_failed', result);
    });

    this.workerPool.on('worker_error', (event) => {
      this.emit('worker_error', event);
    });
  }

  public async processThreatData(threats: ThreatIndicator[]): Promise<TaskResult[]> {
    const tasks = threats.map(threat => this.createTask('threat_analysis', threat));
    return this.processTasks(tasks);
  }

  public async processCorrelation(data: any): Promise<TaskResult> {
    const task = this.createTask('correlation', data, 'high');
    this.workerPool.addTask(task);
    
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Correlation task timeout'));
      }, this.config.taskTimeout);

      const handler = (result: TaskResult) => {
        if (result.taskId === task.id) {
          clearTimeout(timeout);
          this.removeListener('task_completed', handler);
          this.removeListener('task_failed', handler);
          
          if (result.success) {
            resolve(result);
          } else {
            reject(new Error(result.error));
          }
        }
      };

      this.on('task_completed', handler);
      this.on('task_failed', handler);
    });
  }

  private async processTasks(tasks: Task[]): Promise<TaskResult[]> {
    const results: TaskResult[] = [];
    
    for (const task of tasks) {
      this.workerPool.addTask(task);
    }

    return new Promise((resolve) => {
      const handler = (result: TaskResult) => {
        results.push(result);
        
        if (results.length === tasks.length) {
          this.removeListener('task_completed', handler);
          this.removeListener('task_failed', handler);
          resolve(results);
        }
      };

      this.on('task_completed', handler);
      this.on('task_failed', handler);
    });
  }

  private createTask(type: Task['type'], data: any, priority: Task['priority'] = 'medium'): Task {
    return {
      id: `task_${++this.taskCounter}_${Date.now()}`,
      type,
      priority,
      data,
      createdAt: new Date(),
      timeout: this.config.taskTimeout
    };
  }

  public getStats(): any {
    return {
      config: this.config,
      workerPool: this.workerPool.getStats(),
      tasksCreated: this.taskCounter
    };
  }

  public async shutdown(): Promise<void> {
    await this.workerPool.shutdown();
  }
}

// Export classes and types
export { DistributedProcessor, WorkerPool }; 