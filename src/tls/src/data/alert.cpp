#include <tls/data/alert.h>

namespace tls::data {
    void Alert::serialize(Serializer &buffer) {
        buffer.write(level);
        buffer.write(description);
    }

    Alert::Alert(tls::Parser &buffer) {
        level = buffer.read<AlertLevel>();
        description = buffer.read<AlertDescription>();
    }
}