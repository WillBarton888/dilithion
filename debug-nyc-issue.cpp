// Debug version of randomx_init_for_hashing to identify NYC issue
// Add this temporarily to src/crypto/randomx_hash.cpp

extern "C" void randomx_init_for_hashing(const void* key, size_t key_len, int light_mode) {
    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    std::cout << "[NYC DEBUG] Starting RandomX init..." << std::endl;
    std::cout << "[NYC DEBUG] Light mode: " << light_mode << std::endl;

    std::vector<uint8_t> new_key((const uint8_t*)key, (const uint8_t*)key + key_len);
    if (g_randomx_cache != nullptr && g_current_key == new_key && g_is_light_mode == (bool)light_mode) {
        std::cout << "[NYC DEBUG] Already initialized, returning" << std::endl;
        return;
    }

    // Cleanup existing resources
    std::cout << "[NYC DEBUG] Cleaning up existing resources..." << std::endl;
    if (g_randomx_vm != nullptr) {
        randomx_destroy_vm(g_randomx_vm);
        g_randomx_vm = nullptr;
    }
    if (g_randomx_dataset != nullptr) {
        randomx_release_dataset(g_randomx_dataset);
        g_randomx_dataset = nullptr;
    }
    if (g_randomx_cache != nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
    }

    // Force deterministic RandomX flags
    randomx_flags flags = RANDOMX_FLAG_DEFAULT;

    if (!light_mode) {
        flags = static_cast<randomx_flags>(RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_FULL_MEM);
    }

    // Allocate and initialize cache
    std::cout << "[NYC DEBUG] Allocating cache with flags: " << flags << std::endl;
    g_randomx_cache = randomx_alloc_cache(flags);
    if (g_randomx_cache == nullptr) {
        throw std::runtime_error("Failed to allocate RandomX cache");
    }

    std::cout << "[NYC DEBUG] Initializing cache..." << std::endl;
    randomx_init_cache(g_randomx_cache, key, key_len);
    std::cout << "[NYC DEBUG] Cache initialized" << std::endl;

    if (light_mode) {
        std::cout << "[NYC DEBUG] Creating LIGHT mode VM..." << std::endl;
        g_randomx_vm = randomx_create_vm(flags, g_randomx_cache, nullptr);
        if (g_randomx_vm == nullptr) {
            randomx_release_cache(g_randomx_cache);
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to create RandomX VM in light mode");
        }
        std::cout << "[NYC DEBUG] LIGHT mode VM created" << std::endl;
    } else {
        std::cout << "[NYC DEBUG] Entering FULL mode initialization..." << std::endl;

        // Allocate dataset
        g_randomx_dataset = randomx_alloc_dataset(flags);
        if (g_randomx_dataset == nullptr) {
            randomx_release_cache(g_randomx_cache);
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to allocate RandomX dataset");
        }
        std::cout << "[NYC DEBUG] Dataset allocated" << std::endl;

        // Get dataset item count
        unsigned long dataset_item_count = randomx_dataset_item_count();
        std::cout << "[NYC DEBUG] Dataset item count: " << dataset_item_count << std::endl;

        if (dataset_item_count == 0) {
            std::cout << "[NYC DEBUG] ERROR: dataset_item_count is 0!" << std::endl;
            randomx_release_dataset(g_randomx_dataset);
            randomx_release_cache(g_randomx_cache);
            g_randomx_dataset = nullptr;
            g_randomx_cache = nullptr;
            throw std::runtime_error("RandomX dataset_item_count returned 0");
        }

        unsigned int num_threads = std::thread::hardware_concurrency();
        std::cout << "[NYC DEBUG] Hardware concurrency: " << num_threads << std::endl;

        if (num_threads == 0) num_threads = 2;

        // NYC FIX: Force single-threaded to test if multi-threading is the issue
        std::cout << "[NYC DEBUG] FORCING SINGLE THREAD FOR TESTING" << std::endl;
        num_threads = 1;

        std::cout << "[NYC DEBUG] Using " << num_threads << " thread(s) for dataset init" << std::endl;
        std::cout << "[NYC DEBUG] Starting dataset initialization..." << std::endl;

        std::vector<std::thread> init_threads;
        unsigned long items_per_thread = dataset_item_count / num_threads;
        unsigned long items_remainder = dataset_item_count % num_threads;

        std::cout << "[NYC DEBUG] Items per thread: " << items_per_thread << std::endl;
        std::cout << "[NYC DEBUG] Remainder items: " << items_remainder << std::endl;

        auto start_time = std::chrono::steady_clock::now();

        for (unsigned int t = 0; t < num_threads; t++) {
            unsigned long start_item = t * items_per_thread;
            unsigned long count = items_per_thread;

            if (t == num_threads - 1) {
                count += items_remainder;
            }

            std::cout << "[NYC DEBUG] Thread " << t << ": start=" << start_item
                      << ", count=" << count << std::endl;

            init_threads.emplace_back([=]() {
                std::cout << "[NYC DEBUG] Thread " << t << " starting init..." << std::endl;
                randomx_init_dataset(g_randomx_dataset, g_randomx_cache, start_item, count);
                std::cout << "[NYC DEBUG] Thread " << t << " completed init" << std::endl;
            });
        }

        std::cout << "[NYC DEBUG] Waiting for threads to complete..." << std::endl;
        for (size_t i = 0; i < init_threads.size(); i++) {
            std::cout << "[NYC DEBUG] Joining thread " << i << "..." << std::endl;
            init_threads[i].join();
            std::cout << "[NYC DEBUG] Thread " << i << " joined" << std::endl;
        }

        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
        std::cout << "[NYC DEBUG] Dataset initialized in " << duration.count() << "s" << std::endl;

        // Create VM with dataset
        std::cout << "[NYC DEBUG] Creating FULL mode VM..." << std::endl;
        g_randomx_vm = randomx_create_vm(flags, g_randomx_cache, g_randomx_dataset);
        if (g_randomx_vm == nullptr) {
            randomx_release_dataset(g_randomx_dataset);
            randomx_release_cache(g_randomx_cache);
            g_randomx_dataset = nullptr;
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to create RandomX VM in full mode");
        }
        std::cout << "[NYC DEBUG] FULL mode VM created successfully" << std::endl;
    }

    g_current_key = new_key;
    g_is_light_mode = light_mode;
    std::cout << "[NYC DEBUG] RandomX initialization complete!" << std::endl;
}