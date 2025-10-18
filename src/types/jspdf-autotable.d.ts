declare module 'jspdf-autotable' {
  import type jsPDF from 'jspdf'
  const autoTable: (doc: jsPDF, options?: any) => void
  export default autoTable
}
