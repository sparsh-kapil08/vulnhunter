export const MAX_ATTACHMENT_BYTES = 256 * 1024;
export const MAX_ATTACHMENT_CHARS = 20000;
export const MAX_ATTACHMENTS = 3;

export function normalizeAttachment(attachment) {
  if (!attachment) return null;
  if (typeof attachment.name !== 'string' || typeof attachment.content !== 'string') {
    throw new Error('The attachment must include a filename and readable content.');
  }

  const name = attachment.name.replaceAll('\\', '/').split('/').pop().replace(/[\r\n\0]/g, '').slice(0, 255);
  if (!name) throw new Error('The attachment needs a valid filename.');
  if (Buffer.byteLength(attachment.content, 'utf8') > MAX_ATTACHMENT_BYTES) {
    throw new Error('Attachments must be 256 KB or smaller.');
  }

  const truncated = Boolean(attachment.truncated) || attachment.content.length > MAX_ATTACHMENT_CHARS;
  return {
    name,
    content: attachment.content.slice(0, MAX_ATTACHMENT_CHARS),
    truncated
  };
}

export function normalizeAttachments(attachments) {
  if (!attachments) return [];
  const list = Array.isArray(attachments) ? attachments : [attachments];
  if (list.length > MAX_ATTACHMENTS) throw new Error(`Attach no more than ${MAX_ATTACHMENTS} files.`);
  return list.map(normalizeAttachment);
}