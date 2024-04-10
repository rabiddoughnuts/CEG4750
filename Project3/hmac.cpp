#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"

int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    if(argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input filename> <output filename> <key>\n";
        return 1;
    }

    std::string key = argv[3];
    std::string mac, encoded;

    // Read the input file
    std::string message;
    FileSource file(argv[1], true, new StringSink(message));

    // Create the HMAC object
    HMAC<SHA512> hmac((byte*)key.data(), key.size());

    // Calculate the HMAC
    StringSource(message, true, new HashFilter(hmac, new StringSink(mac)));

    // Print the HMAC in hex format
    HexEncoder encoder(new StringSink(encoded));
    StringSource(mac, true, new Redirector(encoder));

    std::cout << "HMAC: " << encoded << std::endl;

    // Write the HMAC to the output file
    FileSink fileSink(argv[2]);
    fileSink.Put((byte*)mac.data(), mac.size());

    return 0;
} 