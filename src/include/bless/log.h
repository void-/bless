#ifndef LOG_H
#define LOG_H

#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <mutex>

namespace Bless
{
  /**
   * @class Log
   * @brief Logging utility appends to a single persistent log file.
   *
   * A singleton is initialized once per process, all regions that need to log
   * get a pointer to the static instance.
   *
   * Example use:
   * <p>
   * @begincode
   * Log.init("out.log"); //only do this once
   * ...
   *
   * Log &localLog = Log.get(); //do this per-class/thread
   * int value = 10;
   *
   * log.log("checkpoint reached"); //normal logging level
   * log.log("value is now: ", value);
   * ...
   * int error = -1;
   * std::string s = "Invalid argument.";
   *
   * log.error("error in function foo", error, "why: ", s); //error level
   * @endcode
   * </p>
   *
   * Sync is probably needed for the output stream.
   *
   * @var std::fstream Log::logFile
   * @brief logging file to append to.
   *
   * @var std::ostream Log::logStream
   * @brief output stream that interfaces to logFile.
   */
  class Log
  {
    public:
      static int init(std::string const &out);

      static Log &getLog();

      template<class... Args>
      void log(Args... args);

      template<class... Args>
      void error(Args... args);

    protected:
      virtual ~Log();

      void logStart(std::string const &level);

      template<class... Args>
      void logLevel(std::string const &level, Args... args);

      template<class First, class... Rest>
      void _log(First car, Rest... cdr);

      template<class Last>
      void _log(Last last);

      std::fstream logFile;
      std::mutex logLock;
    private:
      Log() = default;

      static const std::string normalLevel;
      static const std::string errorLevel;
      static Log instance;
  };

  /**
   * @brief log at the default level
   */
  template<class... Args>
  void Log::log(Args... args)
  {
    logLevel(normalLevel, args...);
  }

  /**
   * @brief log at the error level
   */
  template<class... Args>
  void Log::error(Args... args)
  {
    logLevel(errorLevel, args...);
  }

  /**
   * @brief internal logging implementation at an arbitrary level
   *
   * This is thread safe.
   *
   * @param level the information level to log at
   */
  template<class... Args>
  void Log::logLevel(std::string const &level, Args... args)
  {
    std::lock_guard<std::mutex> lock(logLock);
    logStart(level);
    _log(args...);
  }

  /**
   * @brief log a sequence of arguments in the general case
   */
  template<class First, class... Rest>
  void Log::_log(First car, Rest... cdr)
  {
    logFile << car;
    _log(cdr...);
  }

  /**
   * @brief log the very last argument with a newline.
   */
  template<class Last>
  void Log::_log(Last last)
  {
    logFile << last << "\n";
  }
}
#endif //LOG_H
