#include <bless/log.h>

#include <chrono>
#include <ctime>

namespace Bless
{
  const std::string Log::normalLevel = ".";
  const std::string Log::errorLevel = "E";

  /**
   * @brief destruct the Log by closing the log file.
   */
  Log::~Log()
  {
    logFile.close();
  }

  /**
   * @brief static member function to inititialize the log for an entire
   * process.
   *
   * @warning this should only be called once per process, ideally in
   * main().
   *
   * This is synchronous, but not thread safe.
   *
   * @param out the log file to write to.
   * @return non-zero on failure.
   */
  int Log::init(std::string const &out)
  {
    int error = 0;

    instance.logFile.open(out);

    return error;
  }

  /**
   * @brief get a reference to a static logging instance.
   *
   * @return the Log singleton.
   */
  Log &Log::getLog()
  {
    return instance;
  }

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
   */
  template<class... Args>
  void Log::logLevel(std::string const &level, Args... args)
  {
    //do we need to lock?

    //get the current time
    auto now = std::chrono::system_clock::now();
    std::time_t timestamp = std::chrono::system_clock::to_time_t(now);

    //write the current time and the logging level
    logFile << timestamp << " " << level << "|";
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
   * @brief log a single argument
   */
  template<class Last>
  void Log::_log(Last last)
  {
    logFile << last << "\n";
  }
}
