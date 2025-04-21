#pragma once

#include <gears/SubString.hpp>

namespace Gears::String
{
  namespace Helper
  {
    struct Iterator
    {
    public:
      explicit
      Iterator(const SubString& src) throw ();

      bool
      exhausted() const throw ();

      char
      forward() throw ();

      void
      backward(int step) throw ();

    private:
      const char* current_;
      const char* const END_;
    };
  }

  namespace ToLower
  {
    bool
    to_lower(Helper::Iterator it, char*& dest, size_t& counter) throw ();
  }

  namespace ToUpper
  {
    bool
    to_upper(Helper::Iterator it, char*& dest, size_t& counter) throw ();
  }

  namespace ToUniform
  {
    bool
    to_uniform(Helper::Iterator it, char*& dest, size_t& counter) throw ();
  }

  namespace ToSimplify
  {
    bool
    to_simplify(Helper::Iterator it, char*& dest, size_t& counter) throw ();
  }

  /**
   * Special struct for handy conversion algorithm selection.
   * into case_change methods. Do lower UTF-8 encoding conversion.
   */
  struct Lower
  {
    static const size_t MULTIPLIER = 2;

    static
    bool
    doit(Helper::Iterator in, char*& out, size_t& counter) throw ();
  };

  /**
   * Special struct for handy conversion algorithm selection.
   * into case_change methods. Do simplify UTF-8 encoding conversion.
   */
  struct Simplify
  {
    static const size_t MULTIPLIER = 11;

    static
    bool
    doit(Helper::Iterator in, char*& out, size_t& counter) throw ();
  };

  /**
   * Special struct for handy conversion algorithm selection.
   * into case_change methods. Do uniform UTF-8 encoding conversion.
   */
  struct Uniform
  {
    static const size_t MULTIPLIER = 3;

    static
    bool
    doit(Helper::Iterator in, char*& out, size_t& counter) throw ();
  };

  /**
   * Special struct for handy conversion algorithm selection.
   * into case_change methods. Do upper UTF-8 encoding conversion.
   */
  struct Upper
  {
    static const size_t MULTIPLIER = 2;

    static
    bool
    doit(Helper::Iterator in, char*& out, size_t& counter) throw ();
  };

  /**
   * @param src source UTF-8 string to convert
   * @param dest output iterator to store results of conversion
   * @param counter number of symbols in the converted UTF-8 sequence.
   * @return true if case was changed successfully, false if ill-formed
   * UTF-8 sequence is occurred.
   */
  template <typename Action>
  bool
  case_change(const SubString& src, char*& dest,
    std::size_t* counter = 0) throw ();

  /**
   * @param src source UTF-8 string to convert
   * @param dest string to store results of conversion
   * @param counter number of symbols in the converted UTF-8 sequence.
   * @return true if case was changed successfully, false if ill-formed
   * UTF-8 sequence is occurred.
   */
  template <typename Action, typename Traits, typename Alloc>
  bool
  case_change(const SubString& src,
    std::basic_string<char, Traits, Alloc>& dest,
    std::size_t* counter = 0) /*throw (eh::Exception)*/;
}

//////////////////////////////////////////////////////////////////////////
// Implementation

namespace Gears::String
{
  namespace Helper
  {
    inline
    Iterator::Iterator(const SubString& src) throw ()
      : current_(src.data()), END_(current_ + src.size())
    {
    }

    inline
    bool
    Iterator::exhausted() const throw ()
    {
      return current_ == END_;
    }

    inline
    char
    Iterator::forward() throw ()
    {
      return *current_++;
    }

    inline
    void
    Iterator::backward(int step) throw ()
    {
      current_ -= step;
    }
  }

  inline
  bool
  Lower::doit(Helper::Iterator in, char*& out, size_t& counter) throw ()
  {
    return ToLower::to_lower(in, out, counter);
  }

  inline
  bool
  Simplify::doit(Helper::Iterator in, char*& out, size_t& counter) throw ()
  {
    return ToSimplify::to_simplify(in, out, counter);
  }

  inline
  bool
  Uniform::doit(Helper::Iterator in, char*& out, size_t& counter) throw ()
  {
    return ToUniform::to_uniform(in, out, counter);
  }

  inline
  bool
  Upper::doit(Helper::Iterator in, char*& out, size_t& counter) throw ()
  {
    return ToUpper::to_upper(in, out, counter);
  }

  template <typename Action>
  bool
  case_change(const SubString& src, char*& dest, size_t* counter)
    throw ()
  {
    size_t dummy;
    return Action::doit(Helper::Iterator(src), dest,
      counter ? *counter : dummy);
  }

  template <typename Action, typename Traits, typename Alloc>
  bool
  case_change(const SubString& src,
    std::basic_string<char, Traits, Alloc>& dest,
    std::size_t* counter) /*throw (eh::Exception)*/
  {
    size_t dummy;
    dest.resize(src.size() * Action::MULTIPLIER);
    char* out = &dest[0];
    bool result = Action::doit(Helper::Iterator(src), out,
      counter ? *counter : dummy);
    dest.resize(out - &dest[0]);
    return result;
  }
}
