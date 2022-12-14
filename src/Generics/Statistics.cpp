/**
 * @file   Statistics.cpp
 * @author Karen Aroutiounov
 */

#include <Generics/Statistics.hpp>


//#define TRACE

namespace Generics
{
  namespace Statistics
  {
    //
    // Collection class
    //
    Collection::Collection(DumpRunner* dump_runner)
      /*throw (InvalidArgument, Exception, eh::Exception)*/
      : stat_dumper_(ReferenceCounting::add_ref(dump_runner))
    {
    }

    Collection::Collection(ActiveObjectCallback* callback)
      /*throw (InvalidArgument, Exception, eh::Exception)*/
      : stat_dumper_(new TaskDumpRunner(callback))
    {
    }

    Collection::~Collection() throw ()
    {
      items_.clear();
    }

    void
    Collection::activate_object()
      /*throw (ActiveObject::AlreadyActive, Exception, eh::Exception)*/
    {
      try
      {
        stat_dumper_->activate_object();
      }
      catch (const TaskRunner::Exception& e)
      {
        Stream::Error ostr;
        ostr << FNS << "TaskRunner::Exception:" << e.what();
        throw Exception(ostr);
      }
    }

    void
    Collection::deactivate_object()
      /*throw (Exception, eh::Exception)*/
    {
      try
      {
        stat_dumper_->deactivate_object();
      }
      catch (const TaskRunner::Exception& e)
      {
        Stream::Error ostr;
        ostr << FNS << "TaskRunner::Exception:" << e.what();
        throw Exception(ostr);
      }
    }

    void
    Collection::wait_object()
      /*throw (Exception, eh::Exception)*/
    {
      try
      {
        stat_dumper_->wait_object();
      }
      catch (const TaskRunner::Exception& e)
      {
        Stream::Error ostr;
        ostr << FNS << "TaskRunner::Exception:" << e.what();
        throw Exception(ostr);
      }
    }

    void
    Collection::add(const char* id, StatSink* stat, DumpPolicy* policy)
      /*throw (InvalidArgument, Exception, eh::Exception)*/
    {
      if (id == 0)
      {
        Stream::Error ostr;
        ostr << FNS << "id == 0";
        throw InvalidArgument(ostr);
      }

      WriteGuard_ guard(lock_);

      try
      {
        items_[id] = new Item(id, stat, policy, stat_dumper_);
      }
      catch (const Item::Exception& e)
      {
        Stream::Error ostr;
        ostr << FNS <<
          "Generics::Statistics::Collection::Item::Exception: " << e.what();
        throw InvalidArgument(ostr);
      }
    }

    void
    Collection::dump(std::ostream& ostr)
      /*throw (Exception, eh::Exception)*/
    {
      ReadGuard_ guard(lock_);

      for (ItemMap::iterator item = items_.begin(); item != items_.end();
        ++item)
      {
        item->second->dump(ostr);
        ostr << std::endl;
      }
    }

    //
    // Collection::Item class
    //

    void
    Collection::Item::dump(std::ostream& ostr)
      /*throw (eh::Exception)*/
    {
      Sync::PosixGuard guard(mutex_);

      ostr << "* " << id_.c_str() << " statistics:" << std::endl;
      ostr << current_time().c_str() << std::endl;

      stat_->dump(ostr);
    }

    std::string
    Collection::Item::current_time()
      /*throw (eh::Exception)*/
    {
      return Time::get_time_of_day().get_local_time().format(
        "%a %d %b %Y %H:%M:%S");
    }
  }
}
