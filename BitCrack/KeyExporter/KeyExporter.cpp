#include "KeyExporter.h"
#include "../Logger/Logger.h"
#include "../Util/util.h"

void KeyExporter::defaultStatusCallback(KeySearchStatus status)
{
    // Do nothing
}

KeyExporter::KeyExporter(KeySearchDevice* device, const secp256k1::uint256& startKey, const secp256k1::uint256& endKey, const std::string& outputFile, uint64_t maxFileSize)
{
    _device = device;
    _startKey = startKey;
    _endKey = endKey;
    _outputFile = outputFile;
    _maxFileSize = maxFileSize;
    _running = false;
    _statusInterval = 1000;
    _statusCallback = defaultStatusCallback;
    _total = 0;
    _totalTime = 0;
}

KeyExporter::~KeyExporter()
{
    if (_outputStream.is_open()) {
        _outputStream.close();
    }
}

void KeyExporter::run()
{
    _outputStream.open(_outputFile, std::ios::out | std::ios::binary);
    if (!_outputStream.is_open()) {
        throw KeySearchException("Cannot open output file '" + _outputFile + "'");
    }

    // Write header
    _outputStream << "private_key,x_point" << std::endl;

    _running = true;
    util::Timer timer;
    timer.start();

    uint64_t lastUpdate = 0;
    uint64_t pointsPerIteration = _device->keysPerStep();

    while (_running) {
        std::vector<secp256k1::uint256> randomKeys;
        for (uint64_t i = 0; i < pointsPerIteration; i++) {
            randomKeys.push_back(secp256k1::getRandom(_startKey, _endKey));
        }

        _device->doExportStep(randomKeys);

        std::vector<ExportedKey> exportedKeys;
        _device->getExportedKeys(exportedKeys);

        Logger::log(LogLevel::Info, "Exported " + std::to_string(exportedKeys.size()) + " keys");

        for (const auto& key : exportedKeys) {
			secp256k1::uint256 privateKey(key.privateKey, secp256k1::uint256::BigEndian);
			secp256k1::uint256 x(key.x, secp256k1::uint256::BigEndian);
            _outputStream << privateKey.toString(16) << "," << x.toString(16) << std::endl;
        }

        _total += exportedKeys.size();

        uint64_t t = timer.getTime();
        if (t - lastUpdate >= _statusInterval) {
            KeySearchStatus info;
            info.speed = (double)exportedKeys.size() / ((double)(t - lastUpdate) / 1000.0) / 1000000.0;
            info.total = _total;
            info.totalTime = _totalTime + t;
            _device->getMemoryInfo(info.freeMemory, info.deviceMemory);
            info.deviceName = _device->getDeviceName();
            info.fileSize = _outputStream.tellp();

            _statusCallback(info);
            lastUpdate = t;
        }

        if (_maxFileSize > 0) {
            if (_outputStream.tellp() >= _maxFileSize) {
                Logger::log(LogLevel::Info, "Maximum file size reached. Stopping.");
                _running = false;
            }
        }
    }
}

void KeyExporter::stop()
{
    _running = false;
}

void KeyExporter::setStatusCallback(void(*callback)(KeySearchStatus))
{
    _statusCallback = callback;
}

void KeyExporter::setStatusInterval(uint64_t interval)
{
    _statusInterval = interval;
}
