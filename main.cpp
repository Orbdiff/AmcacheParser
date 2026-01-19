// I asked ChatGPT to generate this, obviously it’s not my program!!!

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <ctime>

void wait(int ms)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

int main()
{
    std::srand((unsigned)std::time(nullptr));

    std::cout << "Initializing system...\n";
    wait(700);

    std::cout << "Loading kernel modules...\n";
    wait(900);

    std::cout << "Checking memory integrity...\n";
    wait(800);

    if (std::rand() % 2)
    {
        std::cout << "\nBOOM 💥\n";
        wait(500);
    }

    std::cout << "\n========================================\n";
    std::cout << ":( Your PC ran into a problem and needs to restart\n\n";
    std::cout << "We're just collecting some error info, and then we'll restart for you.\n";
    std::cout << "0% complete\n";
    wait(1200);

    int progress = 0;
    while (progress < 100)
    {
        progress += std::rand() % 20 + 5;
        if (progress > 100) progress = 100;

        std::cout << "\r" << progress << "% complete";
        std::cout.flush();
        wait(600);
    }

    std::cout << "\n\nStop code: KERNEL_PANIC_AT_3AM\n";
    std::cout << "What failed: totally_not_a_driver.sys\n";
    std::cout << "\n========================================\n";

    wait(1500);
    std::cout << "\nSystem will restart now...\n";
    wait(2000);

    std::cout << "\nJust kidding. Nothing happened 😏\n";
    std::cout << "Have a nice day.\n";

    return 0;
}
