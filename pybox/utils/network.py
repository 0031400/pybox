import asyncio


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    while True:
        data = await reader.read(4096)
        if not data:
            writer.write_eof()
            break
        writer.write(data)
        await writer.drain()


async def close_writer(writer: asyncio.StreamWriter):
    writer.close()
    await writer.wait_closed()


async def bidirectional_relay(
    reader1: asyncio.StreamReader,
    writer1: asyncio.StreamWriter,
    reader2: asyncio.StreamReader,
    writer2: asyncio.StreamWriter,
):
    task1 = asyncio.create_task(relay(reader2, writer1))
    task2 = asyncio.create_task(relay(reader1, writer2))

    done, pending = await asyncio.wait(
        [task1, task2],
        return_when=asyncio.FIRST_COMPLETED,
    )

    for task in pending:
        task.cancel()

    await asyncio.gather(*pending, return_exceptions=True)
