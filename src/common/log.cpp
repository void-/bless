#include <bless/log.h>

#include <chrono>
#include <ctime>

namespace Bless
{
  Log Log::instance;
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
    instance.logFile.open(out, std::ios_base::app);
    return !instance.logFile; //return true if failure
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
   * @brief log the header of a log output line.
   *
   * @param level the logging level.
   */
  void Log::logStart(std::string const &level)
  {
    //get the current time
    auto now = std::chrono::system_clock::now();
    std::time_t timestamp = std::chrono::system_clock::to_time_t(now);

    //write the current time and the logging level
    logFile << timestamp << " " << level << "|";
  }

}
