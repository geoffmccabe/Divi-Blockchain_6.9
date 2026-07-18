#if defined(HAVE_CONFIG_H)
#include "config/divi-config.h"
#endif

// The ZMQ notifier and its factory are only compiled when ZMQ support is
// enabled; build this test only then, so it doesn't reference unlinked symbols.
#if ENABLE_ZMQ

#include <zmq/zmqpublishnotifier.h>
#include <zmq/ZMQNotifierFactory.h>
#include <test/test_only.h>


BOOST_AUTO_TEST_SUITE(ZmqNotifierFactory_tests)

BOOST_AUTO_TEST_CASE(willConstructAnObjectForAllTheKnownNotifierTypes)
{
    for(const std::string& notifierType: GetZMQNotifierTypes())
    {
        auto* notifier = CreateNotifier(notifierType);
        BOOST_CHECK(notifier);
        delete notifier;
    }
}

BOOST_AUTO_TEST_SUITE_END()

#endif // ENABLE_ZMQ
