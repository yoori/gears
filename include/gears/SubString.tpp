// @file String/SubString.tpp

#include <algorithm>
#include <cstdio>

namespace Gears
{
  //
  // CharTraits class
  //

  template <typename CharType>
  int
  CharTraits<CharType>::compare(const CharType* str1, const CharType* str2,
    size_t size) throw ()
  {
    for (const CharType* END = str1 + size; str1 != END;
      str1++, str2++)
    {
      if (!std::char_traits<CharType>::eq(*str1, *str2))
      {
        return std::char_traits<CharType>::lt(*str1, *str2) ? -1 : 1;
      }
    }
    return 0;
  }

  template <typename CharType>
  CharType*
  CharTraits<CharType>::copy(CharType* str1, const CharType* str2,
    size_t size) throw ()
  {
    if (size == 1)
    {
      std::char_traits<CharType>::assign(*str1, *str2);
    }
    else
    {
      std::char_traits<CharType>::copy(str1, str2, size);
    }
    return str1;
  }

  //
  // CheckerNone class
  //

  template <typename CharType>
  void
  CheckerNone<CharType>::check_position(size_t /*length*/, size_t /*pos*/,
    const char* /*error_func*/) throw ()
  {}

  template <typename CharType>
  void
  CheckerNone<CharType>::check_pointer(const CharType* /*ptr*/,
    const char* /*error_func*/) throw ()
  {}

  template <typename CharType>
  void
  CheckerNone<CharType>::check_pointer(const CharType* /*begin*/,
    const CharType* /*end*/, const char* /*error_func*/) throw ()
  {}

  template <typename CharType>
  void
  CheckerNone<CharType>::check_pointer(const CharType* /*ptr*/,
    size_t /*count*/, const char* /*error_func*/) throw ()
  {}


  //
  // CheckerRough class
  //

  template <typename CharType>
  void
  CheckerRough<CharType>::check_position(size_t length, size_t pos,
    const char* error_func) /*throw (OutOfRange)*/
  {
    if (pos > length)
    {
      char error[sizeof(DescriptiveException)];
      std::snprintf(error, sizeof(error),
        "BasicSub%s(): out of range", error_func);
      throw OutOfRange(error);
    }
  }

  template <typename CharType>
  void
  CheckerRough<CharType>::throw_logic_error_(const char* error_func)
    /*throw (LogicError)*/
  {
    char error[sizeof(DescriptiveException)];
    std::snprintf(error, sizeof(error),
      "BasicSub%s(): null pointer dereference", error_func);
    throw LogicError(error);
  }

  template <typename CharType>
  void
  CheckerRough<CharType>::check_pointer(const CharType* ptr,
    const char* error_func) /*throw (LogicError)*/
  {
    if (!ptr)
    {
      throw_logic_error_(error_func);
    }
  }

  template <typename CharType>
  void
  CheckerRough<CharType>::check_pointer(const CharType* ptr, size_t count,
    const char* error_func) /*throw (LogicError)*/
  {
    if (!ptr && count)
    {
      throw_logic_error_(error_func);
    }
  }

  template <typename CharType>
  void
  CheckerRough<CharType>::check_pointer(const CharType* begin,
    const CharType* end, const char* error_func) /*throw (LogicError)*/
  {
    if ((!begin) != (!end) || end < begin)
    {
      throw_logic_error_(error_func);
    }
  }


  //
  // BasicSubString class
  //

  // begin_ + pos
  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::Pointer
  BasicSubString<CharType, Traits, Checker>::begin_plus_position_(
    SizeType position, const char* error_func) const /*throw (OutOfRange)*/
  {
    Checker::check_position(length_, position, error_func);
    return begin_ + position;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::get_available_length_(
    SizeType pos, SizeType count) const throw ()
  {
    return std::min(count, length_ - pos);
  }

  //
  // Public methods
  //

  template <typename CharType, typename Traits, typename Checker>
  template <typename BasicStringTraits, typename Allocator>
  BasicSubString<CharType, Traits, Checker>::BasicSubString(
    const std::basic_string<BasicStringValueType, BasicStringTraits,
      Allocator>& str) noexcept
    : begin_(str.data()), length_(str.size())
  {
  }

  template <typename CharType, typename Traits, typename Checker>
  template <typename BasicStringTraits>
  BasicSubString<CharType, Traits, Checker>::BasicSubString(
    const std::basic_string_view<BasicStringValueType, BasicStringTraits>& str) noexcept
    : begin_(str.data()), length_(str.size())
  {
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>::BasicSubString(Pointer ptr,
    SizeType count) /*throw (LogicError)*/
    : begin_(ptr), length_(count)
  {
    Checker::check_pointer(ptr, count, __FUNCTION__);
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>::BasicSubString(Pointer begin,
    Pointer end) /*throw (LogicError)*/
    : begin_(begin)
  {
    Checker::check_pointer(begin, end, __FUNCTION__);
    length_ = end - begin;
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>::BasicSubString(Pointer ptr)
    /*throw (LogicError)*/
    : begin_(ptr)
  {
    Checker::check_pointer(ptr, __FUNCTION__);
    length_ = Traits::length(begin_);
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>::BasicSubString() throw ()
    : begin_(0), length_(0)
  {
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>::
    BasicSubString(int, SizeType) throw ()
  {
    //Helper::compiler_fail(Helper::constructor_case());
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>&
  BasicSubString<CharType, Traits, Checker>::assign(Pointer ptr,
    SizeType count) /*throw (LogicError)*/
  {
    Checker::check_pointer(ptr, count, __FUNCTION__);
    begin_ = ptr;
    length_ = count;
    return *this;
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>&
  BasicSubString<CharType, Traits, Checker>::assign(Pointer begin,
    Pointer end) /*throw (LogicError)*/
  {
    Checker::check_pointer(begin, end, __FUNCTION__);
    begin_ = begin;
    length_ = end - begin;
    return *this;
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>&
  BasicSubString<CharType, Traits, Checker>::assign(const BasicSubString& str,
    SizeType pos, SizeType count) /*throw (OutOfRange)*/
  {
    begin_ = str.begin_plus_position_(pos, __FUNCTION__);
    length_ = str.get_available_length_(pos, count);
    return *this;
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>&
  BasicSubString<CharType, Traits, Checker>::assign(const BasicSubString& str)
    throw ()
  {
    begin_ = str.begin_;
    length_ = str.length_;
    return *this;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::ConstReference
  BasicSubString<CharType, Traits, Checker>::at(SizeType pos) const
    /*throw (OutOfRange)*/
  {
    return *begin_plus_position_(pos, __FUNCTION__);
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::Reference
  BasicSubString<CharType, Traits, Checker>::at(SizeType pos)
    /*throw (OutOfRange)*/
  {
    return *begin_plus_position_(pos, __FUNCTION__);
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::ConstPointer
  BasicSubString<CharType, Traits, Checker>::begin() const throw ()
  {
    return begin_;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::Pointer
  BasicSubString<CharType, Traits, Checker>::begin() throw ()
  {
    return begin_;
  }

  template <typename CharType, typename Traits, typename Checker>
  void
  BasicSubString<CharType, Traits, Checker>::clear() throw ()
  {
    begin_ = 0;
    length_ = 0;
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>
  BasicSubString<CharType, Traits, Checker>::substr(SizeType pos,
    SizeType count) const /*throw (OutOfRange)*/
  {
    return BasicSubString<CharType, Traits, Checker>(
      begin_plus_position_(pos, __FUNCTION__),
      get_available_length_(pos, count));
  }

  template <typename CharType, typename Traits, typename Checker>
  int
  BasicSubString<CharType, Traits, Checker>::compare(
    const BasicSubString<CharType, Traits, Checker>& str) const throw ()
  {
    const SizeType LEN = std::min(length_, str.length_);
    if (const int RESULT = Traits::compare(begin_, str.begin_, LEN))
    {
      return RESULT;
    }
    return length_ == str.length_ ? 0 : length_ < str.length_ ? -1 : 1;
  }

  template <typename CharType, typename Traits, typename Checker>
  int
  BasicSubString<CharType, Traits, Checker>::compare(SizeType pos1,
    SizeType count1, const BasicSubString& str) const /*throw (OutOfRange)*/
  {
    return substr(pos1, count1).compare(str);
  }

  template <typename CharType, typename Traits, typename Checker>
  int
  BasicSubString<CharType, Traits, Checker>::compare(SizeType pos1,
    SizeType count1, const BasicSubString& str, SizeType pos2,
    SizeType count2) const /*throw (OutOfRange)*/
  {
    return substr(pos1, count1).compare(str.substr(pos2, count2));
  }

  template <typename CharType, typename Traits, typename Checker>
  int
  BasicSubString<CharType, Traits, Checker>::compare(
    ConstPointer str) const /*throw (LogicError)*/
  {
    Checker::check_pointer(str, __FUNCTION__);

    const CharType NUL(0);
    Pointer ptr = begin_;
    ConstPointer END = ptr + length_;
    while (ptr != END)
    {
      const CharType CH(*str++);
      if (Traits::eq(CH, NUL))
      {
        return -1;
      }
      const CharType CH2(*ptr++);
      if (!Traits::eq(CH2, CH))
      {
        return Traits::lt(CH2, CH) ? -1 : 1;
      }
    }
    return Traits::eq(*str, NUL) ? 0 : -1;
  }

  template <typename CharType, typename Traits, typename Checker>
  int
  BasicSubString<CharType, Traits, Checker>::compare(SizeType pos1,
    SizeType count1, ConstPointer ptr) const /*throw (LogicError)*/
  {
    return substr(pos1, count1).compare(ptr);
  }

  template <typename CharType, typename Traits, typename Checker>
  int
  BasicSubString<CharType, Traits, Checker>::compare(SizeType pos1,
    SizeType count1, ConstPointer ptr, SizeType count2) const
    /*throw (LogicError)*/
  {
    return substr(pos1, count1).compare(
      BasicSubString(const_cast<Pointer>(ptr), count2));
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  BasicSubString<CharType, Traits, Checker>::equal(ConstPointer str) const
    /*throw (LogicError)*/
  {
    Checker::check_pointer(str, __FUNCTION__);

    const CharType NUL(0);
    Pointer ptr = begin_;
    const ConstPointer END = ptr + length_;
    while (ptr != END)
    {
      const CharType CH(*str++);
      if (Traits::eq(CH, NUL) || !Traits::eq(*ptr++, CH))
      {
        return false;
      }
    }
    return Traits::eq(*str, NUL);
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  BasicSubString<CharType, Traits, Checker>::equal(
    const BasicSubString& str) const throw ()
  {
    if (str.length_ != length_)
    {
      return false;
    }
    return !Traits::compare(begin_, str.begin_, length_);
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::copy(BasicStringValueType* ptr,
    SizeType count, SizeType pos) const /*throw (OutOfRange, LogicError)*/
  {
    count = get_available_length_(pos, count);
    Checker::check_pointer(ptr, count, __FUNCTION__);

    if (!count)
    {
      return 0;
    }

    Checker::check_position(length_, pos, __FUNCTION__);
    Traits::copy(ptr, begin_ + pos, count);
    return count;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::ConstPointer
  BasicSubString<CharType, Traits, Checker>::data() const throw ()
  {
    return begin_;
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  BasicSubString<CharType, Traits, Checker>::empty() const throw ()
  {
    return !length_;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::ConstPointer
  BasicSubString<CharType, Traits, Checker>::end() const throw ()
  {
    return begin_ + length_;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::Pointer
  BasicSubString<CharType, Traits, Checker>::end() throw ()
  {
    return begin_ + length_;
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>&
  BasicSubString<CharType, Traits, Checker>::erase_front(SizeType count)
    throw ()
  {
    if (begin_)
    {
      count = std::min(count, length_);
      begin_ += count;
      length_ -= count;
    }
    return *this;
  }

  template <typename CharType, typename Traits, typename Checker>
  BasicSubString<CharType, Traits, Checker>&
  BasicSubString<CharType, Traits, Checker>::erase_back(SizeType count)
    throw ()
  {
    if (begin_)
    {
      length_ -= std::min(count, length_);
    }
    return *this;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::find(ValueType ch,
    SizeType pos) const throw ()
  {
    if (pos < length_)
    {
      ConstPointer ptr = Traits::find(begin_ + pos, length_ - pos, ch);
      if (ptr)
      {
        return ptr - begin_;
      }
    }
    return NPOS;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::find(const BasicSubString& str,
    SizeType pos) const throw ()
  {
    if (!str.length_)
    {
      return pos >= length_ ? NPOS : 0;
    }

    SizeType length = get_available_length_(pos, length_);
    if (str.length_ > length)
    {
      return NPOS;
    }

    const ConstPointer END = begin_ + length_;
    const ConstPointer FOUND = std::search(begin_ + pos, END,
      str.begin_, str.begin_ + str.length_, Traits::eq);
    return FOUND != END ? FOUND - begin_ : NPOS;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::find(ConstPointer ptr,
    SizeType pos, SizeType count) const /*throw (LogicError)*/
  {
    return find(BasicSubString<CharType, Traits, Checker>(ptr, count), pos);
  }

#ifdef BASIC_STRING_INTERFACE_IMITATION
  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::find(ConstPointer ptr,
    SizeType pos) const /*throw (LogicError)*/
  {
    return find(BasicSubString<CharType, Traits, Checker>(ptr), pos);
  }
#endif

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::length() const throw ()
  {
    return length_;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::max_size() const throw ()
  {
    return length_;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::rfind(ValueType ch,
    SizeType pos) const throw ()
  {
    if (length_)
    {
      ConstPointer last = begin_ + std::min(length_ - 1, pos);
      for (;; --last)
      {
        if (Traits::eq(*last, ch))
        {
          return last - begin_;
        }
        if (last == begin_)
        {
          return NPOS;
        }
      }
    }
    return NPOS;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::rfind(const BasicSubString& str,
    SizeType pos) const throw ()
  {
    if (str.length_ > length_)
    {
      return NPOS;
    }

    if (pos > length_)
    {
      pos = length_;
    }

    if (!str.length_)
    {
      return pos;
    }

    if (pos > length_ - str.length_)
    {
      pos = length_ - str.length_;
    }

    for (ConstPointer data = begin_ + pos; ; data--)
    {
      if (!Traits::compare(data, str.begin_, str.length_))
      {
        return data - begin_;
      }
      if (data == begin_)
      {
        break;
      }
    }

    return NPOS;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::rfind(ConstPointer ptr,
    SizeType pos, SizeType count) const /*throw (LogicError)*/
  {
    return rfind(BasicSubString<CharType, Traits, Checker>(ptr), pos);
  }

#ifdef BASIC_STRING_INTERFACE_IMITATION
  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::rfind(ConstPointer ptr,
    SizeType pos) const /*throw (LogicError)*/
  {
    return rfind(BasicSubString<CharType, Traits, Checker>(ptr), pos);
  }
#endif

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::SizeType
  BasicSubString<CharType, Traits, Checker>::size() const throw ()
  {
    return length_;
  }

  template <typename CharType, typename Traits, typename Checker>
  void
  BasicSubString<CharType, Traits, Checker>::swap(
    BasicSubString& right) throw ()
  {
    std::swap(begin_, right.begin_);
    std::swap(length_, right.length_);
  }

  template <typename CharType, typename Traits, typename Checker>
  template <typename BasicStringTraits, typename Allocator>
  BasicSubString<CharType, Traits, Checker>&
  BasicSubString<CharType, Traits, Checker>::operator =(
    const std::basic_string<BasicStringValueType, BasicStringTraits,
      Allocator>& str) /*throw (Exception)*/
  {
    begin_ = str.data();
    length_ = str.size();
    return *this;
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::ConstReference
  BasicSubString<CharType, Traits, Checker>::operator [](SizeType pos) const
    /*throw (OutOfRange)*/
  {
    return *begin_plus_position_(pos, __FUNCTION__);
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::Reference
  BasicSubString<CharType, Traits, Checker>::operator [](SizeType pos)
    /*throw (OutOfRange)*/
  {
    return *begin_plus_position_(pos, __FUNCTION__);
  }

  template <typename CharType, typename Traits, typename Checker>
  typename BasicSubString<CharType, Traits, Checker>::BasicString
  BasicSubString<CharType, Traits, Checker>::str() const throw ()
  {
    return BasicString(begin_, length_);
  }

  template <typename CharType, typename Traits, typename Checker>
  template <typename BasicStringTraits, typename Allocator>
  void
  BasicSubString<CharType, Traits, Checker>::assign_to(
    std::basic_string<BasicStringValueType, BasicStringTraits,
      Allocator>& str) const /*throw (Exception)*/
  {
    str.assign(begin_, length_);
  }

  template <typename CharType, typename Traits, typename Checker>
  template <typename BasicStringTraits, typename Allocator>
  void
  BasicSubString<CharType, Traits, Checker>::append_to(
    std::basic_string<BasicStringValueType, BasicStringTraits,
      Allocator>& str) const /*throw (Exception)*/
  {
    str.append(begin_, length_);
  }

  template <typename T>
  void
  Helper::compiler_fail(T& p) throw ()
  {
    //sizeof(T);
  }

  //
  // External functions
  //

  template <typename CharType, typename Traits, typename Checker>
  std::basic_ostream<
    typename BasicSubString<CharType, Traits, Checker>::BasicStringValueType>&
  operator <<(std::basic_ostream<
    typename BasicSubString<CharType, Traits, Checker>::BasicStringValueType>&
      ostr, const BasicSubString<CharType, Traits, Checker>& substr)
    /*throw (Exception)*/
  {
    if (!substr.empty())
    {
      ostr.write(substr.data(), substr.length());
    }
    return ostr;
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator ==(const BasicSubString<CharType, Traits, Checker>& substr,
    typename BasicSubString<CharType, Traits, Checker>::ConstPointer str)
    /*throw (typename BasicSubString<CharType, Traits, Checker>::LogicError)*/
  {
    return substr.equal(str);
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator ==(typename BasicSubString<CharType, Traits, Checker>::ConstPointer
    str, const BasicSubString<CharType, Traits, Checker>& substr)
    /*throw (typename BasicSubString<CharType, Traits, Checker>::LogicError)*/
  {
    return substr.equal(str);
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator ==(const BasicSubString<CharType, Traits, Checker>& left_substr,
    const BasicSubString<CharType, Traits, Checker>& right_substr) throw ()
  {
    return left_substr.equal(right_substr);
  }

  template <typename CharType, typename Traits, typename Checker,
    typename BasicStringTraits, typename Allocator>
  bool
  operator ==(const BasicSubString<CharType, Traits, Checker>& substr,
    const std::basic_string<
      typename BasicSubString<CharType, Traits, Checker>::
      BasicStringValueType, BasicStringTraits, Allocator>& str)
    /*throw (Exception)*/
  {
    return substr.equal(str);
  }

  template <typename CharType, typename Traits, typename Checker,
    typename BasicStringTraits, typename Allocator>
  bool
  operator ==(const std::basic_string<
    typename BasicSubString<CharType, Traits, Checker>::BasicStringValueType,
      BasicStringTraits, Allocator>& str,
    const BasicSubString<CharType, Traits, Checker>& substr)
    /*throw (Exception)*/
  {
    return substr.equal(str);
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator ==(
    int, const BasicSubString<CharType, Traits, Checker>&)
    throw ()
  {
    //Helper::compiler_fail(Helper::pointers_case());
    return false;
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator ==(
    const BasicSubString<CharType, Traits, Checker>&, int)
    throw ()
  {
    //Helper::compiler_fail(Helper::pointers_case());
    return false;
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator !=(const BasicSubString<CharType, Traits, Checker>& substr,
    typename BasicSubString<CharType, Traits, Checker>::ConstPointer str)
    /*throw (typename BasicSubString<CharType, Traits, Checker>::LogicError)*/
  {
    return !substr.equal(str);
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator !=(typename BasicSubString<CharType, Traits, Checker>::
    ConstPointer str, const BasicSubString<CharType, Traits, Checker>& substr)
    /*throw (typename BasicSubString<CharType, Traits, Checker>::LogicError)*/
  {
    return !substr.equal(str);
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator !=(const BasicSubString<CharType, Traits, Checker>& left_substr,
    const BasicSubString<CharType, Traits, Checker>& right_substr) throw ()
  {
    return !left_substr.equal(right_substr);
  }

  template <typename CharType, typename Traits, typename Checker,
    typename BasicStringTraits, typename Allocator>
  bool
  operator !=(const BasicSubString<CharType, Traits, Checker>& substr,
    const std::basic_string<
      typename BasicSubString<CharType, Traits, Checker>::
        BasicStringValueType, BasicStringTraits, Allocator>& str)
    /*throw (Exception)*/
  {
    return !substr.equal(str);
  }

  template <typename CharType, typename Traits, typename Checker,
    typename BasicStringTraits, typename Allocator>
  bool
  operator !=(const std::basic_string<
    typename BasicSubString<CharType, Traits, Checker>::BasicStringValueType,
      BasicStringTraits, Allocator>& str,
    const BasicSubString<CharType, Traits, Checker>& substr)
    /*throw (Exception)*/
  {
    return !substr.equal(str);
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator !=(
    int, const BasicSubString<CharType, Traits, Checker>&)
    throw ()
  {
    //Helper::compiler_fail(Helper::pointers_case());
    return false;
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator !=(
    const BasicSubString<CharType, Traits, Checker>&, int)
    throw ()
  {
    //Helper::compiler_fail(Helper::pointers_case());
    return false;
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator <(const BasicSubString<CharType, Traits, Checker>& substr,
    typename BasicSubString<CharType, Traits, Checker>::ConstPointer str)
    /*throw (typename BasicSubString<CharType, Traits, Checker>::LogicError)*/
  {
    return substr.compare(str) < 0;
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator <(typename BasicSubString<CharType, Traits, Checker>::
    ConstPointer str, const BasicSubString<CharType, Traits, Checker>& substr)
    /*throw (typename BasicSubString<CharType, Traits, Checker>::LogicError)*/
  {
    return !operator <(substr, str);
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator <(const BasicSubString<CharType, Traits, Checker>& left_substr,
    const BasicSubString<CharType, Traits, Checker>& right_substr) throw ()
  {
    return left_substr.compare(right_substr) < 0;
  }

  template <typename CharType, typename Traits, typename Checker,
    typename BasicStringTraits, typename Allocator>
  bool
  operator <(const BasicSubString<CharType, Traits, Checker>& substr,
    const std::basic_string<
      typename BasicSubString<CharType, Traits, Checker>::
      BasicStringValueType, BasicStringTraits, Allocator>& str)
    throw ()
  {
    return substr.compare(str) < 0;
  }

  template <typename CharType, typename Traits, typename Checker,
    typename BasicStringTraits, typename Allocator>
  bool
  operator <(const std::basic_string<
    typename BasicSubString<CharType, Traits, Checker>::BasicStringValueType,
      BasicStringTraits, Allocator>& str,
    const BasicSubString<CharType, Traits, Checker>& substr)
    throw ()
  {
    return substr.compare(str) > 0;
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator <(
    int, const BasicSubString<CharType, Traits, Checker>&)
    throw ()
  {
    //Helper::compiler_fail(Helper::pointers_case());
    return false;
  }

  template <typename CharType, typename Traits, typename Checker>
  bool
  operator <(
    const BasicSubString<CharType, Traits, Checker>&, int)
    throw ()
  {
    //Helper::compiler_fail(Helper::pointers_case());
    return false;
  }

  template <typename Hash,
    typename CharType, typename Traits, typename Checker>
  void
  hash_add(Hash& hash,
    const BasicSubString<CharType, Traits, Checker>& value) throw ()
  {
    hash.add(value.data(), value.size());
  }
} /*Gears*/
