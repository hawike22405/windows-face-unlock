import multiprocessing

if __name__ == "__main__":
    multiprocessing.freeze_support()
    from presence_monitor.monitor import main
    import sys
    if "--self-test" not in sys.argv:
        main()
