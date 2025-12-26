export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

export interface Logger {
  debug(message: string): void;
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

export class ConsoleLogger implements Logger {
  private level: LogLevel;
  private prefix: string;

  constructor(level: LogLevel = LogLevel.INFO, prefix: string = '[Qualys]') {
    this.level = level;
    this.prefix = prefix;
  }

  debug(message: string): void {
    if (this.level <= LogLevel.DEBUG) {
      console.log(`${this.prefix} [DEBUG] ${message}`);
    }
  }

  info(message: string): void {
    if (this.level <= LogLevel.INFO) {
      console.log(`${this.prefix} ${message}`);
    }
  }

  warn(message: string): void {
    if (this.level <= LogLevel.WARN) {
      console.warn(`${this.prefix} [WARN] ${message}`);
    }
  }

  error(message: string): void {
    if (this.level <= LogLevel.ERROR) {
      console.error(`${this.prefix} [ERROR] ${message}`);
    }
  }
}

export class TaskLogger implements Logger {
  private tl: {
    debug: (message: string) => void;
    warning: (message: string) => void;
    error: (message: string) => void;
  };

  constructor(taskLib: {
    debug: (message: string) => void;
    warning: (message: string) => void;
    error: (message: string) => void;
  }) {
    this.tl = taskLib;
  }

  debug(message: string): void {
    this.tl.debug(message);
  }

  info(message: string): void {
    console.log(message);
  }

  warn(message: string): void {
    this.tl.warning(message);
  }

  error(message: string): void {
    this.tl.error(message);
  }
}
