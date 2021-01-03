import winston from "winston";

/**
 * @ignore
 */
export function createLogger(logName: string, logLevel?: string) {
    const logger = winston.createLogger({
        level: logLevel || "error",
        format: winston.format.combine(
            winston.format.timestamp({
                format: "YYYY-MM-DD HH:mm:ss",
            }),
            winston.format.errors({ stack: true }),
            winston.format.splat(),
            winston.format.json()
        ),
        defaultMeta: { service: "vex-" + logName },
        transports: [
            //
            // - Write all logs with level `error` and below to `error.log`
            // - Write all logs with level `info` and below to `combined.log`
            //
            new winston.transports.File({
                filename: "vex:" + logName + ".log",
                level: "error",
            }),
        ],
    });
    //
    // If we're not in production then log to the `console` with the format:
    // `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
    //
    if (process.env.NODE_ENV !== "production") {
        logger.add(
            new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.colorize(),
                    winston.format.simple()
                ),
            })
        );
    }
    return logger;
}
