//
// Created by abolfazl abbasi on 4/22/21.
//

#include "Logger.h"

Logger &Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::error(const char *message, ...) {
    if (!LOGS_ENABLE) {
        return;
    }

    va_list arg;
    va_start(arg, message);
    time_t t = time(nullptr);
    struct tm *currentTime = localtime(&t);

    printf(ANSI_COLOR_RED "%d-%d %02d:%02d:%02d Error: ", currentTime->tm_mon + 1,
           currentTime->tm_mday, currentTime->tm_hour, currentTime->tm_min, currentTime->tm_sec);
    vprintf(message, arg);
    printf(ANSI_COLOR_RESET "\n");
    fflush(stdout);
    va_end(arg);
    va_start(arg, message);
}

void Logger::info(const char *message, ...) {
    if (!LOGS_ENABLE) {
        return;
    }

    va_list arg;
    va_start(arg, message);
    time_t t = time(nullptr);
    struct tm *currentTime = localtime(&t);

    printf("%d-%d %02d:%02d:%02d Info: ", currentTime->tm_mon + 1, currentTime->tm_mday, currentTime->tm_hour,
           currentTime->tm_min, currentTime->tm_sec);
    vprintf(message, arg);
    printf("\n");
    fflush(stdout);
    va_end(arg);
    va_start(arg, message);
}

void Logger::console_log(const char *message, ...) {
    va_list arg;
    va_start(arg, message);
    time_t t = time(nullptr);
    struct tm *currentTime = localtime(&t);

    printf("%d-%d %02d:%02d:%02d Console: ", currentTime->tm_mon + 1, currentTime->tm_mday, currentTime->tm_hour,
           currentTime->tm_min, currentTime->tm_sec);
    vprintf(message, arg);
    printf("\n");
    fflush(stdout);
    va_end(arg);
    va_start(arg, message);
}

void Logger::console_err(const char *message, ...) {
    va_list arg;
    va_start(arg, message);
    time_t t = time(nullptr);
    struct tm *currentTime = localtime(&t);

    printf(ANSI_COLOR_RED "%d-%d %02d:%02d:%02d Console error: ", currentTime->tm_mon + 1,
           currentTime->tm_mday, currentTime->tm_hour, currentTime->tm_min, currentTime->tm_sec);
    printf("for more enter --help");
    vprintf(message, arg);
    printf(ANSI_COLOR_RESET "\n");
    fflush(stdout);
    va_end(arg);
    va_start(arg, message);
}

