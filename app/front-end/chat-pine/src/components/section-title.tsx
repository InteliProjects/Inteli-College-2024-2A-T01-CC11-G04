function SectionTitle({ title }: { title: string }) {
  return (
    <div className="border border-[#F5F5F5] rounded-xl p-4">
      <span className="text-base font-medium">{title}</span>
    </div>
  );
}

export { SectionTitle };
