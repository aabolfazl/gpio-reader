//
// Created by abolfazl on 4/22/21.
//

#ifndef MODBUSCLI_LOGGER_H
#define MODBUSCLI_LOGGER_H

#include <cstdarg>
#include <ctime>
#include <cstdio>

#define LOGS_ENABLE true


#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_RESET   "\x1b[0m"

class Logger {
public:
    static Logger &getInstance();

public:
    static void error(const char *message, ...) __attribute__((format (printf, 1, 2)));

    static void info(const char *message, ...) __attribute__((format (printf, 1, 2)));

    static void console_log(const char *message, ...) __attribute__((format (printf, 1, 2)));

    static void console_err(const char *message, ...) __attribute__((format (printf, 1, 2)));
};

#define log_e Logger::getInstance().error
#define log_i Logger::getInstance().info
#define console_info Logger::getInstance().console_log
#define console_error Logger::getInstance().console_err

#endif //MODBUSCLI_LOGGER_H
