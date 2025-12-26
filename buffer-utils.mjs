export class PacketParser {
  constructor(onPacket) {
    this.buffer = Buffer.alloc(0);
    this.onPacket = onPacket;
  }

  add(data) {
    this.buffer = Buffer.concat([this.buffer, data]);
    this.process();
  }

  process() {
    while (true) {
      if (this.buffer.length < 4) return; // Ждем хотя бы заголовок длины

      const length = this.buffer.readUInt32BE(0);
      
      if (this.buffer.length < 4 + length) return;

      const message = this.buffer.subarray(4, 4 + length);
      this.onPacket(message);

      this.buffer = this.buffer.subarray(4 + length);
    }
  }
}