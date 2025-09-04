// CEG-4750 Information Security
// Brandon Walker
// Meilin Liu
// 04/10/2024
// Project 3

#include "cryptopp/cmac.h"
#include "cryptopp/aes.h"
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

    SecByteBlock key((byte*)argv[3], AES::DEFAULT_KEYLENGTH);
    std::string mac, encoded;

    // Read the input file
    std::string message;
    FileSource file(argv[1], true, new StringSink(message));

    // Create the CMAC object
    CMAC<AES> cmac(key, key.size());

    // Calculate the CMAC
    StringSource(message, true, new HashFilter(cmac, new StringSink(mac)));

    // Print the CMAC in hex format
    HexEncoder encoder(new StringSink(encoded));
    StringSource(mac, true, new Redirector(encoder));

    std::cout << "CMAC: " << encoded << std::endl;

    // Write the CMAC to the output file
    FileSink fileSink(argv[2]);
    fileSink.Put((byte*)mac.data(), mac.size());

    return 0;
}