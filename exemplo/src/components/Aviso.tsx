import DOMPurify from "dompurify";
export const Aviso = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
