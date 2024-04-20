#pragma once

#include "SubString.hpp"

namespace Gears
{
  namespace FunctionHelper
  {
    inline SubString
    get_function_name(const char* function) throw ()
    {
      for (const char* end = function;; end++)
      {
        switch (*end)
        {
        case ' ':
          if (end != function && end[-1] != ',')
          {
            function = end + 1;
          }
          continue;
        case '(':
        case '\0':
          break;
        default:
          continue;
        }
        return SubString(function, end);
      }
    }

    inline SubString
    get_template_info(const char* function) throw ()
    {
      const char with[] = " [with ";
      for (; *function; function++)
      {
        size_t i = 0;
        for (; i < sizeof(with) - 1; i++)
        {
          if (function[i] != with[i])
          {
            break;
          }
        }
        if (i == sizeof(with) - 1)
        {
          break;
        }
      }
      if (!*function)
      {
        return SubString();
      }
      function += sizeof(with) - 1;
      return SubString(function,
        CharTraits<char>::length(function) - 1);
    }
  }
}

/**
 * Base function name. Useful only when a single parameter should be
 * passed to a function (trace_message, for example)
 */
#define FNB Gears::FunctionHelper::get_function_name(__PRETTY_FUNCTION__)
/**
 * Stream function name. Useful with Stream::Error or other stream usage.
 */
#define FNS FNB << "(): "
/**
 * Stream function name with template information.
 * Useful with Stream::Error or other stream usage.
 */
#define FNT FNB << "<" << \
  Gears::FunctionHelper::get_template_info(__PRETTY_FUNCTION__) << \
  ">(): "
/**
 * Designed specially for eh::throw_errno_exception function.
 */
#define FNE FNB, "(): "
