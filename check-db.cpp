#include <iostream>
#include <leveldb/db.h>

int main() {
    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing = false;
    
    leveldb::Status status = leveldb::DB::Open(options, "/c/Users/will/.dilithion-testnet/blocks", &db);
    
    if (!status.ok()) {
        std::cerr << "Failed to open DB: " << status.ToString() << std::endl;
        return 1;
    }
    
    std::string value;
    status = db->Get(leveldb::ReadOptions(), "B", &value);
    if (status.ok()) {
        std::cout << "Best block hash: " << value << std::endl;
    } else {
        std::cout << "Best block key 'B' NOT FOUND in database!" << std::endl;
    }
    
    delete db;
    return 0;
}
