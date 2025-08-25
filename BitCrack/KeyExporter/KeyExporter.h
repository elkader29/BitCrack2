#ifndef _KEY_EXPORTER_H
#define _KEY_EXPORTER_H

#include <string>
#include <vector>
#include <fstream>
#include "../Secp256k1/secp256k1.h"
#include "../KeyFinder/KeySearchDevice.h"

class KeyExporter {
private:
    KeySearchDevice* _device;
    secp256k1::uint256 _startKey;
    secp256k1::uint256 _endKey;
    std::string _outputFile;
    std::ofstream _outputStream;
    uint64_t _maxFileSize;
    uint64_t _statusInterval;
    bool _running;

    uint64_t _total;
    uint64_t _totalTime;

    void(*_statusCallback)(KeySearchStatus);
    static void defaultStatusCallback(KeySearchStatus status);

public:
    KeyExporter(KeySearchDevice* device, const secp256k1::uint256& startKey, const secp256k1::uint256& endKey, const std::string& outputFile, uint64_t maxFileSize);
    ~KeyExporter();

    void run();
    void stop();

    void setStatusCallback(void(*callback)(KeySearchStatus));
    void setStatusInterval(uint64_t interval);
};

#endif
