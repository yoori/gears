#pragma once

#include <vector>
#include <map>

namespace Gears
{
  template<typename KeyType, typename ValueType>
  class Map2Args: public std::map<KeyType, ValueType>
  {
  };

  template<typename KeyType, typename ValueType>
  class Hash2Args: public Generics::GnuHashTable<KeyType, ValueType>
  {
  };

  template<typename KeyType, typename ValueType>
  class RCHash2Args: public ReferenceCounting::HashTable<KeyType, ValueType>
  {
  };

  template<typename KeyType,
           typename MutexType = std::shared_mutex,
    template<typename, typename> class ContainerType = Map2Args>
  class StrictLockMap
  {
  private:
    class LockHolder
    {
    public:
      LockHolder(StrictLockMap& map_val, const KeyType& key_val) noexcept;

      StrictLockMap<KeyType, SyncPolicyType, ContainerType>& map;
      KeyType key;
      mutable MutexType lock;

    protected:
      virtual ~LockHolder() noexcept {}

      virtual bool
      remove_ref_no_delete_() const noexcept;
    };

    using LockHolderPtr = std::shared_ptr<LockHolder>;

    template<typename GuardType>
    struct GuardHolder: public ReferenceCounting::AtomicImpl
    {
      GuardHolder(LockHolderPtr lock_holder_val)
          : lock_holder(std::move(lock_holder_val)),
          guard(lock_holder->lock)
      {}

      LockHolderPtr lock_holder;
      GuardType guard;
    };

  public:
    using ReadGuard = std::shared_ptr<GuardHolder<typename SyncPolicyType::ReadGuard>>;
    using WriteGuard = std::shared_ptr<GuardHolder<typename SyncPolicyType::WriteGuard>>;

  public:
    ReadGuard read_lock(const KeyType& key) noexcept;

    WriteGuard write_lock(const KeyType& key) noexcept;

    typedef ContainerType<KeyType, LockHolderPtr> LockHolderMap;

  protected:
    template<typename GuardType>
    GuardType* get_(const KeyType& key) noexcept
    {
      LockHolder_var holder;
      
      {
        SyncPolicy::WriteGuard guard(map_lock_);

        typename LockHolderMap::const_iterator it = map_.find(key);
        if(it != map_.end())
        {
          holder = ReferenceCounting::add_ref(it->second);
        }
        else
        {
          holder = new LockHolder(*this, key);
          map_.insert(std::make_pair(key, holder.in()));
        }
      }

      return new GuardType(holder);
    }

    void close_i_(const KeyType& key) noexcept;
    
  private:
    std::mutex map_lock_;
    LockHolderMap map_;
  };

  template<typename KeyType, typename MutexType = std::shared_mutex>
  class NoAllocLockMap
  {
  private:
    template<typename GuardType>
    struct GuardHolder: public ReferenceCounting::AtomicImpl
    {
      GuardHolder(typename SyncPolicyType::Mutex& lock_val)
        : guard(lock_val)
      {}

      GuardType guard;
    };

  public:
    using ReadGuard = std::shared_ptr<GuardHolder<typename SyncPolicyType::ReadGuard>>;
    using WriteGuard = std::shared_ptr<GuardHolder<typename SyncPolicyType::WriteGuard>>;

    struct LockWrap: public SyncPolicyType::Mutex
    {
      LockWrap()
      {}

      LockWrap(const LockWrap&)
        : SyncPolicyType::Mutex()
      {}

      LockWrap&
      operator=(const LockWrap&)
      {
        return *this;
      }
    };

    typedef std::vector<LockWrap> LockArray;

  public:
    NoAllocLockMap(unsigned long size = 100) noexcept;

    ReadGuard
    read_lock(const KeyType& key) noexcept;

    WriteGuard
    write_lock(const KeyType& key) noexcept;

  protected:
    template<typename GuardType>
    GuardType* get_(const KeyType& key) noexcept
    {
      unsigned long lock_i = key.hash() % locks_.size();
      return new GuardType(locks_[lock_i]);
    }

  private:
    LockArray locks_;
  };

  template<typename KeyType,
    typename SyncPolicyType = Sync::Policy::PosixThreadRW>
  class LockMap: public NoAllocLockMap<KeyType, SyncPolicyType>
  {
  public:
    LockMap(unsigned long size = 100) noexcept
      : NoAllocLockMap<KeyType, SyncPolicyType>(size)
    {}
  };
}

namespace Gears
{
  // StrictStrictLockMap
  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::LockHolder::LockHolder(
    StrictLockMap<KeyType, SyncPolicyType, ContainerType>& map_val,
    const KeyType& key_val) noexcept
    : map(map_val), key(key_val)
  {}

  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  bool
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::LockHolder::remove_ref_no_delete_() const noexcept
  {
    SyncPolicy::WriteGuard guard(map.map_lock_);
    if(ReferenceCounting::AtomicImpl::remove_ref_no_delete_())
    {
      map.close_i_(key);
      return true;
    }
    return false;
  }

  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  typename StrictLockMap<KeyType, SyncPolicyType, ContainerType>::ReadGuard
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::read_lock(const KeyType& key)
    noexcept
  {
    return ReadGuard(get_<
      GuardHolder<typename SyncPolicyType::ReadGuard> >(key));
  }

  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  typename StrictLockMap<KeyType, SyncPolicyType, ContainerType>::WriteGuard
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::write_lock(const KeyType& key)
    noexcept
  {
    return WriteGuard(get_<
      GuardHolder<typename SyncPolicyType::WriteGuard> >(key));
  }

  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  void
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::close_i_(const KeyType& key) noexcept
  {
    typename LockHolderMap::size_type erased_keys = map_.erase(key);
    (void)erased_keys;
    assert(erased_keys);
  }

  // NoAllocLockMap
  template<typename KeyType, typename SyncPolicyType>
  NoAllocLockMap<KeyType, SyncPolicyType>::NoAllocLockMap(
    unsigned long size)
    noexcept
  {
    locks_.resize(size);
  }

  template<typename KeyType, typename SyncPolicyType>
  typename NoAllocLockMap<KeyType, SyncPolicyType>::ReadGuard
  NoAllocLockMap<KeyType, SyncPolicyType>::read_lock(
    const KeyType& key)
    noexcept
  {
    return ReadGuard(get_<
      GuardHolder<typename SyncPolicyType::ReadGuard> >(key));
  }

  template<typename KeyType, typename SyncPolicyType>
  typename NoAllocLockMap<KeyType, SyncPolicyType>::WriteGuard
  NoAllocLockMap<KeyType, SyncPolicyType>::write_lock(
    const KeyType& key)
    noexcept
  {
    return WriteGuard(get_<
      GuardHolder<typename SyncPolicyType::WriteGuard> >(key));
  }
}
